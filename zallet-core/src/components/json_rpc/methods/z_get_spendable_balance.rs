use std::time::Duration;

use anyhow::Context;
use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::WalletRead;
use zcash_protocol::value::Zatoshis;

use crate::components::{
    database::Database,
    json_rpc::{pir::Pir, server::LegacyCode, utils::value_from_zatoshis},
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

const TIMEOUT: Duration = Duration::from_secs(25);

pub(crate) async fn call(wallet: &Database, pir: Option<&Pir>) -> Response {
    calculate(wallet, pir)
        .await
        .map_err(|error| LegacyCode::Misc.with_message(error.to_string()))
}

async fn calculate(wallet: &Database, pir: Option<&Pir>) -> anyhow::Result<ResultType> {
    let handle = wallet.handle().await?;
    let notes = handle.pir_ironwood_notes()?;
    let last_scanned = handle
        .block_fully_scanned()?
        .map(|block| block.block_height());
    drop(handle);
    if notes.is_empty() {
        return Ok(ResultType {
            balance: value_from_zatoshis(Zatoshis::ZERO).to_string(),
            wallet_scanned_through: last_scanned.map(u32::from),
            pir_checked_through: None,
        });
    }
    let last_scanned = last_scanned.context("wallet has not scanned any blocks")?;
    let checked = pir
        .context("PIR is disabled")?
        .check_notes(notes, last_scanned, TIMEOUT)
        .await?;

    let mut total = Zatoshis::ZERO;
    for note in checked.notes {
        total = (total + note.value()).context("spendable balance overflow")?;
    }
    Ok(ResultType {
        balance: value_from_zatoshis(total).to_string(),
        wallet_scanned_through: Some(u32::from(last_scanned)),
        pir_checked_through: Some(checked.checked_through),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::ResultType;

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
