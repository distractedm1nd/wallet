//! `start` subcommand

use abscissa_core::{FrameworkError, Runnable, config};
use anyhow::{Context, bail};
use spendability_pir_client::{P2pPirNode, SpendClient, WitnessClient, ZcashNetwork};
use tokio::{pin, select, task::AbortHandle};
use zcash_client_backend::data_api::WalletRead;
use zcash_client_sqlite::PirIronwoodWitness;
use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters as _};

use crate::{
    cli::StartCmd,
    commands::AsyncRunnable,
    components::{
        TaskHandle,
        chain::{Chain, ChainFactory, ChainView, check_consensus_compatibility},
        database::Database,
        json_rpc::JsonRpc,
        sync::{WalletSync, status},
    },
    config::ZalletConfig,
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

const PIR_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

fn first_unchecked_ironwood_height(
    last_scanned: BlockHeight,
    activation: BlockHeight,
) -> BlockHeight {
    std::cmp::max(
        BlockHeight::from_u32(u32::from(last_scanned).saturating_add(1)),
        activation,
    )
}

async fn try_pir_shortcut<C: Chain>(
    config: &ZalletConfig,
    db: &Database,
    chain: &C,
) -> anyhow::Result<()> {
    if config.pir.bootstrap_peers.is_empty() {
        return Ok(());
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

    let result = tokio::time::timeout(PIR_STARTUP_TIMEOUT, async {
        let session = client.session().await?;
        let health = session.health().await?;
        if health.nullifier.phase != "serving" {
            bail!("PIR nullifier provider is not serving");
        }

        let db_handle = db.handle().await?;
        let notes = db_handle.pir_ironwood_notes()?;
        if notes.is_empty() {
            return Ok(());
        }
        let last_scanned = db_handle
            .block_fully_scanned()?
            .context("wallet has not scanned any blocks")?
            .block_height();
        drop(db_handle);

        let spend = SpendClient::connect_p2p(session.clone(), network).await?;
        let ironwood_activation = chain
            .params()
            .activation_height(NetworkUpgrade::Nu6_3)
            .context("NU6.3 activation height is not configured")?;
        if spend.earliest_height()
            > u64::from(u32::from(first_unchecked_ironwood_height(
                last_scanned,
                ironwood_activation,
            )))
        {
            bail!("PIR nullifier retention does not cover the unscanned range");
        }
        let mut unspent_notes = Vec::with_capacity(notes.len());
        for note in &notes {
            if !spend.is_spent(note.nullifier()).await? {
                unspent_notes.push(note);
            }
        }
        if unspent_notes.is_empty() {
            return Ok(());
        }
        if health.witness.phase != "serving" {
            bail!("PIR witness provider is not serving");
        }

        let witness_client = WitnessClient::connect_p2p(session, network).await?;
        if spend.latest_height() < witness_client.anchor_height() {
            bail!("PIR datasets do not share a usable snapshot");
        }
        let anchor_height = BlockHeight::from_u32(
            witness_client
                .anchor_height()
                .try_into()
                .context("PIR anchor height exceeds the Zcash height range")?,
        );
        let chain_state = chain
            .snapshot()
            .await?
            .tree_state_as_of(anchor_height)
            .await?
            .context("PIR anchor is above the chain tip")?;
        let chain_root = chain_state.final_ironwood_tree().root().to_bytes();

        for note in &unspent_notes {
            if note.mined_height() > anchor_height {
                bail!("PIR anchor predates a wallet note");
            }
        }
        let positions = unspent_notes
            .iter()
            .map(|note| u64::from(note.position()))
            .collect::<Vec<_>>();
        let fetched_witnesses = witness_client.get_witnesses(&positions).await?;
        let mut witnesses = Vec::with_capacity(unspent_notes.len());
        for (note, witness) in unspent_notes.into_iter().zip(fetched_witnesses) {
            if witness.anchor_root != chain_root {
                bail!("PIR witness root does not match the chain");
            }
            witnesses.push(PirIronwoodWitness::new(
                note.note_id(),
                note.position(),
                witness.siblings,
            ));
        }

        db.handle()
            .await?
            .replace_pir_ironwood_witnesses(anchor_height, chain_root, &witnesses)?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("PIR startup timed out")));

    node.shutdown().await;
    result
}

#[cfg(zallet_build = "wallet")]
use crate::components::keystore::KeyStore;

/// Owns cancellation for every task spawned by `zallet start`.
struct StartupTaskOwner {
    abort_handles: Vec<AbortHandle>,
}

impl StartupTaskOwner {
    fn new(first_task: &TaskHandle) -> Self {
        Self {
            abort_handles: vec![first_task.abort_handle()],
        }
    }

    fn include(&mut self, task: &TaskHandle) {
        self.abort_handles.push(task.abort_handle());
    }
}

impl Drop for StartupTaskOwner {
    fn drop(&mut self) {
        for abort_handle in &self.abort_handles {
            abort_handle.abort();
        }
    }
}

async fn supervise_zallet_tasks(
    task_owner: StartupTaskOwner,
    chain_indexer_task_handle: TaskHandle,
    rpc_task_handle: TaskHandle,
    wallet_sync_steady_state_task_handle: TaskHandle,
    wallet_sync_recover_history_task_handle: TaskHandle,
    wallet_sync_batch_decryptor_task_handle: TaskHandle,
    wallet_sync_data_requests_task_handle: TaskHandle,
) -> Result<(), Error> {
    // Retain abort-on-drop ownership while the supervisor itself is cancellable.
    info!("Spawned Zallet tasks");

    // ongoing tasks.
    pin!(chain_indexer_task_handle);
    pin!(rpc_task_handle);
    pin!(wallet_sync_steady_state_task_handle);
    pin!(wallet_sync_recover_history_task_handle);
    pin!(wallet_sync_batch_decryptor_task_handle);
    pin!(wallet_sync_data_requests_task_handle);

    // Every supervised task is ongoing, so the first exit shuts down Zallet. Preserve
    // the selected task's inner result so a backend-runtime or sync failure makes the
    // process fail rather than being converted to success.
    let result = select! {
        chain_indexer_join_result = &mut chain_indexer_task_handle => {
            let chain_indexer_result = chain_indexer_join_result
                .expect("unexpected panic in the chain indexer task");
            info!(?chain_indexer_result, "Chain indexer task exited");
            chain_indexer_result
        }

        rpc_join_result = &mut rpc_task_handle => {
            let rpc_server_result = rpc_join_result
                .expect("unexpected panic in the RPC task");
            info!(?rpc_server_result, "RPC task exited");
            rpc_server_result
        }

        wallet_sync_join_result = &mut wallet_sync_steady_state_task_handle => {
            let wallet_sync_result = wallet_sync_join_result
                .expect("unexpected panic in the wallet steady-state sync task");
            info!(?wallet_sync_result, "Wallet steady-state sync task exited");
            wallet_sync_result
        }

        wallet_sync_join_result = &mut wallet_sync_recover_history_task_handle => {
            let wallet_sync_result = wallet_sync_join_result
                .expect("unexpected panic in the wallet recover-history sync task");
            info!(?wallet_sync_result, "Wallet recover-history sync task exited");
            wallet_sync_result
        }

        wallet_sync_join_result = &mut wallet_sync_batch_decryptor_task_handle => {
            let wallet_sync_result = wallet_sync_join_result
                .expect("unexpected panic in the wallet batch decryptor task");
            info!(?wallet_sync_result, "Wallet batch decryptor task exited");
            wallet_sync_result
        }

        wallet_sync_join_result = &mut wallet_sync_data_requests_task_handle => {
            let wallet_sync_result = wallet_sync_join_result
                .expect("unexpected panic in the wallet data-requests sync task");
            info!(?wallet_sync_result, "Wallet data-requests sync task exited");
            wallet_sync_result
        }
    };

    info!("An ongoing Zallet task exited; cancelling the remaining tasks");
    // Dropping `task_owner` aborts every task it owns. The task whose exit `select!`
    // just observed is already complete, so aborting it is a no-op; the remaining
    // siblings are cancelled. `select!` drops the loser branches' futures, but the
    // pinned `JoinHandle`s remain live until `task_owner` is dropped here.
    drop(task_owner);

    result
}

impl StartCmd {
    /// Runs `zallet start` against the chain backend produced by `factory`.
    pub(crate) async fn run_with<F: ChainFactory>(factory: &F) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        Self::run_with_config(&config, factory).await
    }

    async fn run_with_config<F: ChainFactory>(
        config: &ZalletConfig,
        factory: &F,
    ) -> Result<(), Error> {
        // BETA: Warn when currently-unused config options are set.
        let warn_unused =
            |option: &str| warn!("{}", fl!("warn-config-unused", option = option.to_string()));
        // TODO: https://github.com/zcash/zallet/issues/199
        if config.builder.spend_zeroconf_change.is_some() {
            warn_unused("builder.spend_zeroconf_change");
        }
        // TODO: https://github.com/zcash/zallet/issues/200
        if config.builder.tx_expiry_delta.is_some() {
            warn_unused("builder.tx_expiry_delta");
        }
        // These are accepted, documented, and migrated from zcashd config, but nothing
        // reads them at runtime, so a migrated wallet silently loses the behaviour.
        if config.external.export_dir.is_some() {
            warn_unused("external.export_dir");
        }
        if config.external.notify.is_some() {
            warn_unused("external.notify");
        }

        // Construct a structurally admitted chain backend before opening the wallet database.
        let (chain, chain_indexer_task_handle) = factory.build(config).await?;
        let mut task_owner = StartupTaskOwner::new(&chain_indexer_task_handle);

        // Refuse to start if the backing full node already follows consensus rules we
        // cannot interpret. If the only incompatibilities are still in the future, this
        // returns the height at which to shut down before reaching them.
        let shutdown_height = check_consensus_compatibility(&chain).await?;

        let db = Database::open(config).await?;
        {
            let mut db_handle = db.handle().await?;
            db_handle.clear_pir_ironwood_witnesses().map_err(|error| {
                ErrorKind::Init.context(format!("failed to disable stale PIR state: {error}"))
            })?;
        }
        if let Err(error) = try_pir_shortcut(config, &db, &chain).await {
            warn!(%error, "PIR shortcut unavailable; continuing with ordinary sync");
        }
        #[cfg(zallet_build = "wallet")]
        let keystore = KeyStore::new(config, db.clone())?;

        // Build the decryptor up front so the RPC server has its handle before the initial scan.
        let (decryptor_handle, decryptor_engine) = WalletSync::build_decryptor();

        // The sync engine publishes its status over this channel; the RPC server reads it
        // to gate balance and spend methods while the wallet is not trustworthy.
        let (sync_status_writer, sync_status_reader) =
            status::channel(config.sync.lock_threshold());

        // Launch RPC server.
        let rpc_task_handle = JsonRpc::spawn(
            config,
            db.clone(),
            #[cfg(zallet_build = "wallet")]
            keystore,
            chain.clone(),
            #[cfg(zallet_build = "wallet")]
            decryptor_handle.clone(),
            sync_status_reader,
        )
        .await?;
        task_owner.include(&rpc_task_handle);

        // Start the wallet sync process.
        let (
            wallet_sync_steady_state_task_handle,
            wallet_sync_recover_history_task_handle,
            wallet_sync_batch_decryptor_task_handle,
            wallet_sync_data_requests_task_handle,
        ) = WalletSync::spawn(
            config,
            db,
            chain,
            shutdown_height,
            decryptor_handle,
            decryptor_engine,
            sync_status_writer,
        )
        .await?;

        // WalletSync transfers these handles immediately before returning; take over
        // cancellation ownership before this startup future reaches another await.
        task_owner.include(&wallet_sync_steady_state_task_handle);
        task_owner.include(&wallet_sync_recover_history_task_handle);
        task_owner.include(&wallet_sync_batch_decryptor_task_handle);
        task_owner.include(&wallet_sync_data_requests_task_handle);

        supervise_zallet_tasks(
            task_owner,
            chain_indexer_task_handle,
            rpc_task_handle,
            wallet_sync_steady_state_task_handle,
            wallet_sync_recover_history_task_handle,
            wallet_sync_batch_decryptor_task_handle,
            wallet_sync_data_requests_task_handle,
        )
        .await
    }
}

impl AsyncRunnable for StartCmd {
    async fn run(&self) -> Result<(), Error> {
        crate::application::chain_runtime().run_start().await
    }
}

impl Runnable for StartCmd {
    fn run(&self) {
        self.run_on_runtime();
        info!("Shutting down Zallet");
    }
}

impl config::Override<ZalletConfig> for StartCmd {
    fn override_config(&self, config: ZalletConfig) -> Result<ZalletConfig, FrameworkError> {
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::Duration;

    use super::{
        StartCmd, StartupTaskOwner, first_unchecked_ironwood_height, supervise_zallet_tasks,
    };
    use crate::{
        components::{
            TaskHandle,
            chain::{ChainFactory, MockChain},
        },
        config::ZalletConfig,
        error::{Error, ErrorKind},
    };
    use rusqlite::Connection;

    /// The error returned when the fake factory cannot admit its backend.
    const BACKEND_ADMISSION_FAILURE: &str = "required chain backend service is unavailable";
    /// The error returned by a supervised task in the propagation test.
    const SUPERVISED_TASK_FAILURE: &str = "supervised task failed";
    /// A compatible prior version that makes a database reopen observably record this build.
    const PRIOR_ZALLET_VERSION: &str = "0.1.0-beta.0";

    #[test]
    fn pir_coverage_starts_at_ironwood_or_after_the_wallet_tip() {
        let activation = 100.into();
        assert_eq!(
            first_unchecked_ironwood_height(50.into(), activation),
            activation
        );
        assert_eq!(
            first_unchecked_ironwood_height(150.into(), activation),
            151.into()
        );
    }

    struct AdmissionRejectingFactory {
        build_was_attempted: Arc<AtomicBool>,
    }

    struct TaskCancellationProbe(mpsc::Sender<()>);

    impl Drop for TaskCancellationProbe {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    async fn observed_pending_task(task_cancelled: mpsc::Sender<()>) -> TaskHandle {
        let cancellation_probe = TaskCancellationProbe(task_cancelled);
        let (task_started, task_started_receiver) = futures::channel::oneshot::channel();
        let task = tokio::spawn(async move {
            let _cancellation_probe = cancellation_probe;
            let _ = task_started.send(());
            std::future::pending::<Result<(), Error>>().await
        });
        task_started_receiver
            .await
            .expect("cancellation-observed task starts");
        task
    }

    async fn assert_task_cancelled(task_cancelled: mpsc::Receiver<()>) {
        tokio::task::spawn_blocking(move || task_cancelled.recv_timeout(Duration::from_secs(1)))
            .await
            .expect("cancellation observer does not panic")
            .expect("pre-supervision task is cancelled");
    }

    struct ConsensusIncompatibleFactory {
        task_cancelled: mpsc::Sender<()>,
    }

    impl ChainFactory for ConsensusIncompatibleFactory {
        type Chain = MockChain;

        const NAME: &'static str = "consensus-incompatible";

        async fn build(&self, _config: &ZalletConfig) -> Result<(Self::Chain, TaskHandle), Error> {
            let task = observed_pending_task(self.task_cancelled.clone()).await;

            Ok((MockChain::reporting(Vec::new(), u32::MAX), task))
        }
    }

    impl ChainFactory for AdmissionRejectingFactory {
        type Chain = MockChain;

        const NAME: &'static str = "admission-rejecting";

        async fn build(&self, _config: &ZalletConfig) -> Result<(Self::Chain, TaskHandle), Error> {
            self.build_was_attempted.store(true, Ordering::SeqCst);
            Err(ErrorKind::Init.context(BACKEND_ADMISSION_FAILURE).into())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backend_admission_failure_does_not_create_wallet_database() {
        crate::i18n::load_languages(&[]);

        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let wallet_db_path = config.wallet_db_path();
        let build_was_attempted = Arc::new(AtomicBool::new(false));
        let factory = AdmissionRejectingFactory {
            build_was_attempted: build_was_attempted.clone(),
        };

        let error = StartCmd::run_with_config(&config, &factory)
            .await
            .expect_err("backend admission rejects startup");

        assert!(
            build_was_attempted.load(Ordering::SeqCst),
            "backend construction must run before wallet initialization",
        );
        assert!(
            error.to_string().contains(BACKEND_ADMISSION_FAILURE),
            "unexpected startup error: {error}",
        );
        assert!(
            !wallet_db_path.exists(),
            "backend admission failure must not create or migrate the wallet database",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backend_admission_failure_does_not_migrate_existing_wallet_database() {
        crate::i18n::load_languages(&[]);

        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let wallet_db_path = config.wallet_db_path();

        let database = super::Database::open(&config)
            .await
            .expect("creates a current wallet database");
        drop(database);

        let connection = Connection::open(&wallet_db_path).expect("opens wallet database");
        let updated = connection
            .execute(
                "UPDATE ext_zallet_db_version_metadata
                 SET version = ?1
                 WHERE rowid = (
                    SELECT MAX(rowid) FROM ext_zallet_db_version_metadata
                 )",
                [PRIOR_ZALLET_VERSION],
            )
            .expect("marks the database as last opened by the prior version");
        assert_eq!(updated, 1, "setup updates exactly one version record");
        drop(connection);

        let build_was_attempted = Arc::new(AtomicBool::new(false));
        let factory = AdmissionRejectingFactory {
            build_was_attempted: build_was_attempted.clone(),
        };

        let error = StartCmd::run_with_config(&config, &factory)
            .await
            .expect_err("backend admission rejects startup");

        assert!(build_was_attempted.load(Ordering::SeqCst));
        assert!(
            error.to_string().contains(BACKEND_ADMISSION_FAILURE),
            "unexpected startup error: {error}",
        );

        let connection = Connection::open(&wallet_db_path).expect("reopens wallet database");
        let latest_version: String = connection
            .query_row(
                "SELECT version
                 FROM ext_zallet_db_version_metadata
                 ORDER BY rowid DESC
                 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("reads latest recorded Zallet version");
        assert_eq!(
            latest_version, PRIOR_ZALLET_VERSION,
            "backend admission failure must not run migrations or record this Zallet version",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn consensus_rejection_cancels_admitted_backend_task_before_wallet_initialization() {
        crate::i18n::load_languages(&[]);

        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let (task_cancelled, task_cancelled_receiver) = mpsc::channel();
        let factory = ConsensusIncompatibleFactory { task_cancelled };

        StartCmd::run_with_config(&config, &factory)
            .await
            .expect_err("consensus incompatibility rejects startup");

        assert_task_cancelled(task_cancelled_receiver).await;
        assert!(
            !config.wallet_db_path().exists(),
            "consensus rejection must happen before wallet initialization",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wallet_sync_initialization_error_cancels_chain_and_rpc_tasks() {
        let (chain_task_cancelled, chain_task_cancelled_receiver) = mpsc::channel();
        let chain_task = observed_pending_task(chain_task_cancelled).await;
        let (rpc_task_cancelled, rpc_task_cancelled_receiver) = mpsc::channel();
        let rpc_task = observed_pending_task(rpc_task_cancelled).await;

        let initialization: Result<(), Error> = async {
            let mut task_owner = StartupTaskOwner::new(&chain_task);
            task_owner.include(&rpc_task);
            Err(ErrorKind::Init
                .context("simulated wallet sync initialization failure")
                .into())
        }
        .await;

        initialization.expect_err("late startup initialization fails");
        assert_task_cancelled(chain_task_cancelled_receiver).await;
        assert_task_cancelled(rpc_task_cancelled_receiver).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelling_task_supervision_stops_every_zallet_task() {
        let (chain_cancelled, chain_cancelled_receiver) = mpsc::channel();
        let chain_task = observed_pending_task(chain_cancelled).await;
        let (rpc_cancelled, rpc_cancelled_receiver) = mpsc::channel();
        let rpc_task = observed_pending_task(rpc_cancelled).await;
        let (steady_cancelled, steady_cancelled_receiver) = mpsc::channel();
        let steady_task = observed_pending_task(steady_cancelled).await;
        let (recovery_cancelled, recovery_cancelled_receiver) = mpsc::channel();
        let recovery_task = observed_pending_task(recovery_cancelled).await;
        let (batch_cancelled, batch_cancelled_receiver) = mpsc::channel();
        let batch_task = observed_pending_task(batch_cancelled).await;
        let (requests_cancelled, requests_cancelled_receiver) = mpsc::channel();
        let requests_task = observed_pending_task(requests_cancelled).await;

        let mut task_owner = StartupTaskOwner::new(&chain_task);
        task_owner.include(&rpc_task);
        task_owner.include(&steady_task);
        task_owner.include(&recovery_task);
        task_owner.include(&batch_task);
        task_owner.include(&requests_task);

        {
            let supervisor = supervise_zallet_tasks(
                task_owner,
                chain_task,
                rpc_task,
                steady_task,
                recovery_task,
                batch_task,
                requests_task,
            );
            tokio::pin!(supervisor);
            assert!(
                futures::poll!(&mut supervisor).is_pending(),
                "all supervised tasks are pending",
            );
        }

        assert_task_cancelled(chain_cancelled_receiver).await;
        assert_task_cancelled(rpc_cancelled_receiver).await;
        assert_task_cancelled(steady_cancelled_receiver).await;
        assert_task_cancelled(recovery_cancelled_receiver).await;
        assert_task_cancelled(batch_cancelled_receiver).await;
        assert_task_cancelled(requests_cancelled_receiver).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn task_supervision_propagates_the_selected_task_error() {
        let chain_task = tokio::spawn(async {
            Err::<(), Error>(ErrorKind::Generic.context(SUPERVISED_TASK_FAILURE).into())
        });
        let (rpc_cancelled, rpc_cancelled_receiver) = mpsc::channel();
        let rpc_task = observed_pending_task(rpc_cancelled).await;
        let (steady_cancelled, steady_cancelled_receiver) = mpsc::channel();
        let steady_task = observed_pending_task(steady_cancelled).await;
        let (recovery_cancelled, recovery_cancelled_receiver) = mpsc::channel();
        let recovery_task = observed_pending_task(recovery_cancelled).await;
        let (batch_cancelled, batch_cancelled_receiver) = mpsc::channel();
        let batch_task = observed_pending_task(batch_cancelled).await;
        let (requests_cancelled, requests_cancelled_receiver) = mpsc::channel();
        let requests_task = observed_pending_task(requests_cancelled).await;

        let mut task_owner = StartupTaskOwner::new(&chain_task);
        task_owner.include(&rpc_task);
        task_owner.include(&steady_task);
        task_owner.include(&recovery_task);
        task_owner.include(&batch_task);
        task_owner.include(&requests_task);

        let error = supervise_zallet_tasks(
            task_owner,
            chain_task,
            rpc_task,
            steady_task,
            recovery_task,
            batch_task,
            requests_task,
        )
        .await
        .expect_err("a supervised task error must fail zallet start");

        assert!(
            error.to_string().contains(SUPERVISED_TASK_FAILURE),
            "unexpected supervision error: {error}",
        );
        assert_task_cancelled(rpc_cancelled_receiver).await;
        assert_task_cancelled(steady_cancelled_receiver).await;
        assert_task_cancelled(recovery_cancelled_receiver).await;
        assert_task_cancelled(batch_cancelled_receiver).await;
        assert_task_cancelled(requests_cancelled_receiver).await;
    }
}
