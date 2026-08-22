//! `z_sendfromaccount` — send funds from an account in one shot.
//!
//! Unlike `z_sendmany`, the source of funds is an account UUID together with an
//! explicit, isolating `fund_source`, rather than an address. The transaction
//! is assembled by driving a PCZT through the same pipeline the `pczt_*`
//! methods expose — create, prove, sign, extract — so this method differs from
//! that flow only in doing it in one call and broadcasting the result.

use jsonrpsee::core::{JsonValue, RpcResult};
use secrecy::ExposeSecret;
use zcash_client_backend::data_api::{Account, WalletRead};
use zcash_encoding::ReverseHex;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::TxId;

use super::pczt_common::encode_pczt_base64;
use super::{pczt_create, pczt_extract, pczt_prove, pczt_sign};
use crate::{
    components::{
        chain::Chain,
        database::{Database, DbHandle},
        json_rpc::{
            fund_source::FundSource,
            payments::{
                AmountParameter, SendResult, build_request, confirmations_policy_for_minconf,
                parse_privacy_policy, verify_and_broadcast_transactions,
            },
            pir::Pir,
            server::LegacyCode,
            utils::parse_account_parameter,
        },
        keystore::KeyStore,
        sync::{SyncStatus, SyncStatusReader},
    },
    fl,
};

/// Response to a `z_sendfromaccount` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The result of a `z_sendfromaccount` request: the resulting transaction ID(s).
pub(crate) type ResultType = SendResult;

pub(super) const PARAM_ACCOUNT_DESC: &str = "The UUID of the account to send the funds from.";
pub(super) const PARAM_FUND_SOURCE_DESC: &str = "Where funds may be drawn from: \"orchard\", \"ironwood\", \"sapling\", \"any_transparent\", or an array \
     of transparent addresses.";
pub(super) const PARAM_RECIPIENTS_DESC: &str =
    "An array of JSON objects representing the amounts to send.";
pub(super) const PARAM_RECIPIENTS_REQUIRED: bool = true;
pub(super) const PARAM_MINCONF_DESC: &str = "Only use funds confirmed at least this many times.";
pub(super) const PARAM_PRIVACY_POLICY_DESC: &str =
    "Policy for what information leakage is acceptable.";

async fn wallet_handle(wallet: &Database) -> RpcResult<DbHandle> {
    wallet
        .handle()
        .await
        .map_err(|_| jsonrpsee::types::ErrorCode::InternalError.into())
}

fn should_prepare_pir(status: &SyncStatus, fund_source: &FundSource) -> bool {
    matches!(status, SyncStatus::CatchingUp { .. }) && *fund_source == FundSource::Ironwood
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn call<C: Chain>(
    wallet: Database,
    keystore: KeyStore,
    chain: C,
    sync_status: SyncStatusReader,
    pir: Option<Pir>,
    account: JsonValue,
    fund_source: JsonValue,
    recipients: Vec<AmountParameter>,
    minconf: Option<u32>,
    privacy_policy: String,
) -> Response {
    let mut handle = wallet_handle(&wallet).await?;

    let request = build_request(&recipients)?;

    let account_id = parse_account_parameter(handle.as_ref(), &keystore, &account).await?;

    // Fetch the account up front: it both validates that the account exists and
    // provides the key derivation needed to sign the transaction.
    let account = handle
        .as_ref()
        .get_account(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InvalidParameter.with_message(fl!("err-account-not-found")))?;

    let fund_source = FundSource::parse(&fund_source, handle.params())?;

    let derivation = account.source().key_derivation().ok_or_else(|| {
        LegacyCode::InvalidAddressOrKey.with_message(fl!("err-account-no-payment-source"))
    })?;

    // This method sends in one shot, so the caller must acknowledge the privacy
    // implications up front: the policy is required, not optional. It is
    // enforced at proposal time here, and acknowledged again at the signing
    // step below.
    let privacy_policy = parse_privacy_policy(Some(&privacy_policy))?;

    let confirmations_policy = confirmations_policy_for_minconf(minconf)?;

    let pir_result = if should_prepare_pir(&sync_status.status(), &fund_source)
        && handle
            .as_ref()
            .pir_ironwood_anchor_height()
            .map_err(|error| LegacyCode::Database.with_message(error.to_string()))?
            .is_none()
    {
        drop(handle);
        let result = match pir.as_ref() {
            Some(pir) => pir.prepare_witnesses(&wallet, chain.clone()).await,
            None => Err(anyhow::anyhow!("PIR is disabled")),
        };
        handle = wallet_handle(&wallet).await?;
        Some(result)
    } else {
        None
    };

    match sync_status.status() {
        SyncStatus::Synced => (),
        SyncStatus::CatchingUp { .. } if fund_source == FundSource::Ironwood => {
            if let Some(result) = pir_result {
                result.map_err(|error| LegacyCode::Wallet.with_message(error.to_string()))?;
            }
            if handle
                .as_ref()
                .pir_ironwood_anchor_height()
                .map_err(|error| LegacyCode::Database.with_message(error.to_string()))?
                .is_none()
            {
                return Err(LegacyCode::Wallet
                    .with_static("PIR witnesses are not available for an Ironwood send"));
            }
        }
        SyncStatus::CatchingUp { .. } | SyncStatus::Recovering { .. } => {
            sync_status.ensure_available()?;
        }
    }

    let (pczt, _required_policy, proposal) = pczt_create::build_pczt(
        &mut handle,
        &account,
        &fund_source.spend_policy(),
        request,
        privacy_policy,
        confirmations_policy,
    )?;

    let seed = keystore
        .decrypt_seed(derivation.seed_fingerprint())
        .await
        .map_err(|e| match e.kind() {
            // TODO: Improve internal error types.
            //       https://github.com/zcash/zallet/issues/256
            crate::error::ErrorKind::Generic if e.to_string() == "Wallet is locked" => {
                LegacyCode::WalletUnlockNeeded.with_message(e.to_string())
            }
            _ => LegacyCode::Database.with_message(e.to_string()),
        })?;
    let ufvk = UnifiedSpendingKey::from_seed(
        handle.params(),
        seed.expose_secret(),
        derivation.account_index(),
    )
    .map_err(|e| LegacyCode::InvalidAddressOrKey.with_message(e.to_string()))?
    .to_unified_full_viewing_key();

    // The remaining steps acquire their own wallet handles; do not hold this
    // one across them.
    drop(handle);

    // Drive the PCZT through the same pipeline the `pczt_*` methods expose.
    let proved = pczt_prove::call(&encode_pczt_base64(pczt)?).await?;

    // `strict` guarantees that every input was signed: this wallet created the
    // PCZT from its own account, so an unsigned input is a failure, not a
    // multi-party hand-off. The caller's policy doubles as the acknowledgement
    // that signing requires.
    let signed = pczt_sign::call(
        wallet_handle(&wallet).await?,
        keystore.clone(),
        &proved.pczt,
        Some(privacy_policy.to_string()),
        Some(true),
    )
    .await?;

    // Extraction verifies the proofs and signatures, and records the
    // transaction in the wallet so its inputs are marked pending-spent before
    // broadcast.
    let extracted = pczt_extract::call(wallet_handle(&wallet).await?, &signed.pczt).await?;

    // The user-facing txid string is byte-reversed hex, per Bitcoin convention.
    let txid = ReverseHex::decode(&extracted.txid)
        .map(TxId::from_bytes)
        .ok_or_else(|| LegacyCode::Misc.with_static("Failed to decode txid"))?;

    let handle = wallet_handle(&wallet).await?;
    verify_and_broadcast_transactions(
        handle.as_ref(),
        chain,
        account_id,
        &ufvk,
        &proposal,
        vec![txid],
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::should_prepare_pir;
    use crate::components::{json_rpc::fund_source::FundSource, sync::SyncStatus};

    #[test]
    fn only_catch_up_ironwood_sends_prepare_pir() {
        let catching_up = SyncStatus::CatchingUp {
            fully_synced: Some(100.into()),
            tip: 200.into(),
        };
        assert!(should_prepare_pir(&catching_up, &FundSource::Ironwood));
        assert!(!should_prepare_pir(&catching_up, &FundSource::Sapling));
        assert!(!should_prepare_pir(
            &SyncStatus::Synced,
            &FundSource::Ironwood
        ));
    }
}
