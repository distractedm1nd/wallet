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

/// Total PIR-reported spendable Ironwood balance, denominated in ZEC.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(String);

const TIMEOUT: Duration = Duration::from_secs(25);

pub(crate) async fn call(wallet: &Database, config: &ZalletConfig) -> Response {
    calculate(wallet, config)
        .await
        .map(|value| ResultType(value_from_zatoshis(value).to_string()))
        .map_err(|error| LegacyCode::Misc.with_message(error.to_string()))
}

async fn calculate(wallet: &Database, config: &ZalletConfig) -> anyhow::Result<Zatoshis> {
    let handle = wallet.handle().await?;
    let notes = handle.pir_ironwood_notes()?;
    if notes.is_empty() {
        return Ok(Zatoshis::ZERO);
    }
    let last_scanned = handle
        .block_fully_scanned()?
        .context("wallet has not scanned any blocks")?
        .block_height();
    drop(handle);

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

        let mut total = Zatoshis::ZERO;
        for note in notes {
            if !spend.is_spent(note.nullifier()).await? {
                total = (total + note.value()).context("spendable balance overflow")?;
            }
        }
        Ok::<_, anyhow::Error>(total)
    })
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("PIR balance query timed out")));

    node.shutdown().await;
    result
}

#[cfg(test)]
mod tests {
    use zcash_protocol::value::{COIN, Zatoshis};

    use crate::components::json_rpc::utils::value_from_zatoshis;

    #[test]
    fn renders_exact_zec_balance() {
        assert_eq!(
            value_from_zatoshis(Zatoshis::const_from_u64(COIN + 23)).to_string(),
            "1.00000023"
        );
    }
}
