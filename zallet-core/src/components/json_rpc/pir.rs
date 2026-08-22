use std::{cmp::max, time::Duration};

use anyhow::{Context, bail};
use spendability_pir_client::{
    P2pPirClient, P2pPirNode, P2pPirSession, SpendClient, WitnessClient, ZcashNetwork,
};
use tokio::sync::watch;
use zcash_client_backend::data_api::WalletRead;
use zcash_client_sqlite::{PirIronwoodNote, PirIronwoodWitness};
use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters as _};

use crate::{
    components::{
        chain::{Chain, ChainView},
        database::Database,
    },
    config::ZalletConfig,
};

const SEND_TIMEOUT: Duration = Duration::from_secs(120);
const RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct Pir {
    network: ZcashNetwork,
    activation: BlockHeight,
    clients: watch::Receiver<Option<P2pPirClient>>,
    _shutdown: watch::Sender<()>,
}

pub(crate) struct CheckedNotes {
    pub(crate) notes: Vec<PirIronwoodNote>,
    pub(crate) checked_through: u64,
}

struct Check {
    notes: Vec<PirIronwoodNote>,
    checked_through: u64,
    witness_serving: bool,
}

impl Pir {
    pub(crate) fn start(config: &ZalletConfig) -> Option<Self> {
        if config.pir.bootstrap_peers.is_empty() {
            return None;
        }
        let network = match config.consensus.network {
            NetworkType::Main => ZcashNetwork::Main,
            NetworkType::Test => ZcashNetwork::Test,
            NetworkType::Regtest => {
                tracing::warn!("PIR does not support regtest");
                return None;
            }
        };
        let Some(activation) = config
            .consensus
            .network()
            .activation_height(NetworkUpgrade::Nu6_3)
        else {
            tracing::warn!("PIR requires a configured NU6.3 activation height");
            return None;
        };
        let (client_tx, clients) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        tokio::spawn(run(
            config.pir.bootstrap_peers.clone(),
            network,
            client_tx,
            shutdown_rx,
        ));
        Some(Self {
            network,
            activation,
            clients,
            _shutdown: shutdown_tx,
        })
    }

    pub(crate) async fn check_notes(
        &self,
        notes: Vec<PirIronwoodNote>,
        last_scanned: BlockHeight,
        timeout: Duration,
    ) -> anyhow::Result<CheckedNotes> {
        tokio::time::timeout(timeout, self.check_notes_inner(notes, last_scanned))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("PIR query timed out")))
    }

    async fn check_notes_inner(
        &self,
        notes: Vec<PirIronwoodNote>,
        last_scanned: BlockHeight,
    ) -> anyhow::Result<CheckedNotes> {
        let session = self.session().await?;
        let checked = self.check_notes_on(session, notes, last_scanned).await?;
        Ok(CheckedNotes {
            notes: checked.notes,
            checked_through: checked.checked_through,
        })
    }

    async fn check_notes_on(
        &self,
        session: P2pPirSession,
        notes: Vec<PirIronwoodNote>,
        last_scanned: BlockHeight,
    ) -> anyhow::Result<Check> {
        let health = session.health().await?;
        if health.nullifier.phase != "serving" {
            bail!("PIR nullifier provider is not serving");
        }
        let spend = SpendClient::connect_p2p(session, self.network).await?;
        if spend.earliest_height() > u64::from(max(last_scanned + 1, self.activation)) {
            bail!("PIR nullifier retention does not cover the unscanned range");
        }

        let checked_through = spend.latest_height();
        let mut unspent = Vec::with_capacity(notes.len());
        for note in notes {
            if !spend.is_spent(note.nullifier()).await? {
                unspent.push(note);
            }
        }
        Ok(Check {
            notes: unspent,
            checked_through,
            witness_serving: health.witness.phase == "serving",
        })
    }

    async fn session(&self) -> anyhow::Result<P2pPirSession> {
        let mut clients = self.clients.clone();
        loop {
            let client = clients.borrow().clone();
            if let Some(client) = client {
                return Ok(client.session().await?);
            }
            clients.changed().await.context("PIR networking stopped")?;
        }
    }

    pub(crate) async fn prepare_witnesses<C: Chain>(
        &self,
        wallet: &Database,
        chain: C,
    ) -> anyhow::Result<()> {
        let mut handle = wallet.handle().await?;
        handle.clear_pir_ironwood_witnesses()?;
        let notes = handle.pir_ironwood_notes()?;
        if notes.is_empty() {
            return Ok(());
        }
        let last_scanned = handle
            .block_fully_scanned()?
            .context("wallet has not scanned any blocks")?
            .block_height();
        drop(handle);

        tokio::time::timeout(
            SEND_TIMEOUT,
            self.prepare_witnesses_inner(wallet, chain, notes, last_scanned),
        )
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("PIR query timed out")))
    }

    async fn prepare_witnesses_inner<C: Chain>(
        &self,
        wallet: &Database,
        chain: C,
        notes: Vec<PirIronwoodNote>,
        last_scanned: BlockHeight,
    ) -> anyhow::Result<()> {
        let session = self.session().await?;
        let checked = self
            .check_notes_on(session.clone(), notes, last_scanned)
            .await?;
        if checked.notes.is_empty() {
            return Ok(());
        }
        if !checked.witness_serving {
            bail!("PIR witness provider is not serving");
        }

        let witness_client = WitnessClient::connect_p2p(session, self.network).await?;
        if checked.checked_through < witness_client.anchor_height() {
            bail!("PIR datasets do not share a usable snapshot");
        }
        let anchor_height = BlockHeight::from_u32(
            witness_client
                .anchor_height()
                .try_into()
                .context("PIR anchor height exceeds the Zcash height range")?,
        );
        let chain_root = chain
            .snapshot()
            .await?
            .tree_state_as_of(anchor_height)
            .await?
            .context("PIR anchor is above the chain tip")?
            .final_ironwood_tree()
            .root()
            .to_bytes();

        if checked
            .notes
            .iter()
            .any(|note| note.mined_height() > anchor_height)
        {
            bail!("PIR anchor predates a wallet note");
        }
        let positions = checked
            .notes
            .iter()
            .map(|note| u64::from(note.position()))
            .collect::<Vec<_>>();
        let fetched = witness_client.get_witnesses(&positions).await?;
        let witnesses = checked
            .notes
            .into_iter()
            .zip(fetched)
            .map(|(note, witness)| {
                if witness.anchor_root != chain_root {
                    bail!("PIR witness root does not match the chain");
                }
                Ok(PirIronwoodWitness::new(
                    note.note_id(),
                    note.position(),
                    witness.siblings,
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        wallet.handle().await?.replace_pir_ironwood_witnesses(
            anchor_height,
            chain_root,
            &witnesses,
        )?;
        Ok(())
    }
}

async fn run(
    bootstrap_peers: Vec<String>,
    network: ZcashNetwork,
    clients: watch::Sender<Option<P2pPirClient>>,
    mut shutdown: watch::Receiver<()>,
) {
    loop {
        let spawn = P2pPirNode::spawn_ephemeral(bootstrap_peers.clone(), network);
        tokio::select! {
            result = spawn => match result {
                Ok((node, client)) => {
                    clients.send_replace(Some(client));
                    let _ = shutdown.changed().await;
                    node.shutdown().await;
                    return;
                }
                Err(error) => tracing::warn!("Failed to start PIR networking: {error}"),
            },
            _ = shutdown.changed() => return,
        }
        tokio::select! {
            _ = tokio::time::sleep(RETRY_DELAY) => (),
            _ = shutdown.changed() => return,
        }
    }
}
