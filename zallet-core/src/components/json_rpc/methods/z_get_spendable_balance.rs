use std::time::Duration;

use anyhow::{Context, bail};
use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use spendability_pir_client::{P2pPirNode, SpendClient, ZcashNetwork};
use zcash_client_backend::data_api::WalletRead;
use zcash_protocol::{
    consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters as _},
    value::Zatoshis,
};

use crate::{
    components::{
        database::Database,
        json_rpc::{server::LegacyCode, utils::value_from_zatoshis},
    },
    config::ZalletConfig,
};

pub(crate) type Response = RpcResult<ResultType>;

/// PIR-reported spendable Ironwood balance and the heights used to calculate it.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    /// Total PIR-reported spendable Ironwood balance, denominated in ZEC.
    balance: String,

    /// Height through which the wallet had scanned when it loaded the known notes.
    wallet_scanned_through: Option<u32>,

    /// Height through which the PIR provider checked the known note nullifiers.
    pir_checked_through: Option<u64>,
}

struct Calculation {
    value: Zatoshis,
    wallet_scanned_through: Option<u32>,
    pir_checked_through: Option<u64>,
}

const TIMEOUT: Duration = Duration::from_secs(25);

pub(crate) async fn call(wallet: &Database, config: &ZalletConfig) -> Response {
    calculate(wallet, config)
        .await
        .map(|result| ResultType {
            balance: value_from_zatoshis(result.value).to_string(),
            wallet_scanned_through: result.wallet_scanned_through,
            pir_checked_through: result.pir_checked_through,
        })
        .map_err(|error| LegacyCode::Misc.with_message(error.to_string()))
}

async fn calculate(wallet: &Database, config: &ZalletConfig) -> anyhow::Result<Calculation> {
    let handle = wallet.handle().await?;
    let notes = handle.pir_ironwood_notes()?;
    let last_scanned = handle
        .block_fully_scanned()?
        .map(|block| block.block_height());
    drop(handle);
    if notes.is_empty() {
        return Ok(Calculation {
            value: Zatoshis::ZERO,
            wallet_scanned_through: last_scanned.map(u32::from),
            pir_checked_through: None,
        });
    }
    let last_scanned = last_scanned.context("wallet has not scanned any blocks")?;

    if config.pir.bootstrap_peers.is_empty() {
        bail!("PIR is disabled");
    }
    let network = match config.consensus.network {
        NetworkType::Main => ZcashNetwork::Main,
        NetworkType::Test => ZcashNetwork::Test,
        NetworkType::Regtest => bail!("PIR does not support regtest"),
    };
    tokio::fs::create_dir_all(config.pir_identity_dir()).await?;
    let (node, client) = P2pPirNode::spawn(
        config.pir_identity_dir(),
        config.pir.bootstrap_peers.clone(),
        network,
    )
    .await?;

    // ponytail: one short-lived client per RPC; share one if concurrent calls matter.
    let result = tokio::time::timeout(TIMEOUT, async {
        let session = client.session().await?;
        if session.health().await?.nullifier.phase != "serving" {
            bail!("PIR nullifier provider is not serving");
        }
        let spend = SpendClient::connect_p2p(session, network).await?;
        let activation = config
            .consensus
            .network()
            .activation_height(NetworkUpgrade::Nu6_3)
            .context("NU6.3 activation height is not configured")?;
        let first_unchecked = std::cmp::max(
            BlockHeight::from_u32(u32::from(last_scanned).saturating_add(1)),
            activation,
        );
        if spend.earliest_height() > u64::from(u32::from(first_unchecked)) {
            bail!("PIR nullifier retention does not cover the unscanned range");
        }

        let pir_checked_through = spend.latest_height();
        let mut total = Zatoshis::ZERO;
        for note in notes {
            if !spend.is_spent(note.nullifier()).await? {
                total = (total + note.value()).context("spendable balance overflow")?;
            }
        }
        Ok::<_, anyhow::Error>(Calculation {
            value: total,
            wallet_scanned_through: Some(u32::from(last_scanned)),
            pir_checked_through: Some(pir_checked_through),
        })
    })
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("PIR balance query timed out")));

    node.shutdown().await;
    result
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use zcash_protocol::value::{COIN, Zatoshis};

    use super::ResultType;
    use crate::components::json_rpc::utils::value_from_zatoshis;

    #[test]
    fn renders_exact_zec_balance() {
        assert_eq!(
            value_from_zatoshis(Zatoshis::const_from_u64(COIN + 23)).to_string(),
            "1.00000023"
        );
    }

    #[test]
    fn serializes_balance_and_checked_heights() {
        assert_eq!(
            serde_json::to_value(ResultType {
                balance: "1.00000023".into(),
                wallet_scanned_through: Some(100),
                pir_checked_through: Some(200),
            })
            .unwrap(),
            json!({
                "balance": "1.00000023",
                "wallet_scanned_through": 100,
                "pir_checked_through": 200,
            }),
        );
    }
}
