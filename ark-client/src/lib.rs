use crate::wallet::BoardingWallet;
use crate::wallet::OnchainWallet;
use ark_core::default_vtxo::DefaultVtxo;
use ark_core::generate_incoming_vtxo_transaction_history;
use ark_core::generate_outgoing_vtxo_transaction_history;
use ark_core::server;
use ark_core::server::ListVtxo;
use ark_core::server::Round;
use ark_core::server::VtxoOutPoint;
use ark_core::ArkAddress;
use ark_core::ArkTransaction;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::Txid;
use futures::Future;
use jiff::Timestamp;
use std::sync::Arc;

pub mod error;
pub mod round;
pub mod wallet;

mod coin_select;
mod send_vtxo;
mod unilateral_exit;
mod utils;

pub use error::Error;

pub struct OfflineClient<B, W> {
    // TODO: We could introduce a generic interface so that consumers can use either GRPC or REST.
    network_client: ark_grpc::Client,
    pub name: String,
    pub kp: Keypair,
    blockchain: Arc<B>,
    secp: Secp256k1<All>,
    wallet: Arc<W>,
}

pub struct Client<B, W> {
    inner: OfflineClient<B, W>,
    pub server_info: server::Info,
}

#[derive(Clone, Copy, Debug)]
pub struct ExplorerUtxo {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub confirmation_blocktime: Option<u64>,
    pub is_spent: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct SpendStatus {
    pub spend_txid: Option<Txid>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OffChainBalance {
    pending: Amount,
    confirmed: Amount,
}

impl OffChainBalance {
    pub fn pending(&self) -> Amount {
        self.pending
    }

    pub fn confirmed(&self) -> Amount {
        self.confirmed
    }

    pub fn total(&self) -> Amount {
        self.pending + self.confirmed
    }
}

pub trait Blockchain {
    fn find_outpoints(
        &self,
        address: &Address,
    ) -> impl Future<Output = Result<Vec<ExplorerUtxo>, Error>> + Send;

    fn find_tx(
        &self,
        txid: &Txid,
    ) -> impl Future<Output = Result<Option<Transaction>, Error>> + Send;

    fn get_output_status(
        &self,
        txid: &Txid,
        vout: u32,
    ) -> impl Future<Output = Result<SpendStatus, Error>> + Send;

    fn broadcast(&self, tx: &Transaction) -> impl Future<Output = Result<(), Error>> + Send;
}

impl<B, W> OfflineClient<B, W>
where
    B: Blockchain,
    W: BoardingWallet + OnchainWallet,
{
    pub fn new(
        name: String,
        kp: Keypair,
        blockchain: Arc<B>,
        wallet: Arc<W>,
        ark_server_url: String,
    ) -> Self {
        let secp = Secp256k1::new();

        let network_client = ark_grpc::Client::new(ark_server_url);

        Self {
            network_client,
            name,
            kp,
            blockchain,
            secp,
            wallet,
        }
    }

    pub async fn connect(mut self) -> Result<Client<B, W>, Error> {
        self.network_client.connect().await?;
        let server_info = self.network_client.get_info().await?;

        tracing::debug!(
            name = self.name,
            ark_server_url = ?self.network_client,
            "Connected to Ark server"
        );

        Ok(Client {
            inner: self,
            server_info,
        })
    }
}

impl<B, W> Client<B, W>
where
    B: Blockchain,
    W: BoardingWallet + OnchainWallet,
{
    // At the moment we are always generating the same address.
    pub fn get_offchain_address(&self) -> (ArkAddress, DefaultVtxo) {
        let server_info = &self.server_info;

        let (server, _) = server_info.pk.x_only_public_key();
        let (owner, _) = self.inner.kp.public_key().x_only_public_key();

        let default_vtxo = DefaultVtxo::new(
            self.secp(),
            server,
            owner,
            server_info.unilateral_exit_delay,
            server_info.network,
        );

        let ark_address = default_vtxo.to_ark_address();

        (ark_address, default_vtxo)
    }

    pub fn get_offchain_addresses(&self) -> Vec<(ArkAddress, DefaultVtxo)> {
        let address = self.get_offchain_address();

        vec![address]
    }

    // At the moment we are always generating the same address.
    pub fn get_boarding_address(&self) -> Result<Address, Error> {
        let server_info = &self.server_info;
        let boarding_output = self.inner.wallet.new_boarding_output(
            server_info.pk.x_only_public_key().0,
            server_info.unilateral_exit_delay,
            &server_info.boarding_descriptor_template,
            server_info.network,
        )?;

        Ok(boarding_output.address().clone())
    }

    pub fn get_boarding_addresses(&self) -> Result<Vec<Address>, Error> {
        let address = self.get_boarding_address()?;

        Ok(vec![address])
    }

    pub async fn list_vtxos(&self) -> Result<ListVtxo, Error> {
        let addresses = self.get_offchain_addresses();

        let mut vtxos = ListVtxo {
            spendable: Vec::new(),
            spent: Vec::new(),
        };

        for (address, _) in addresses.into_iter() {
            let mut list = self.network_client().list_vtxos(&address).await?;
            vtxos.spendable.append(&mut list.spendable);
            vtxos.spent.append(&mut list.spent);
        }

        Ok(vtxos)
    }

    pub async fn get_round(&self, round_txid: String) -> Result<Option<Round>, Error> {
        let round = self.network_client().get_round(round_txid).await?;

        Ok(round)
    }

    pub async fn spendable_vtxos(&self) -> Result<Vec<(Vec<VtxoOutPoint>, DefaultVtxo)>, Error> {
        let addresses = self.get_offchain_addresses();

        let now = Timestamp::now();

        let mut spendable = vec![];
        for (address, vtxo) in addresses.into_iter() {
            let vtxos = self.network_client().list_vtxos(&address).await?;
            let explorer_utxos = self.blockchain().find_outpoints(vtxo.address()).await?;

            let mut vtxo_outpoints = Vec::new();
            for vtxo_outpoint in vtxos.spendable {
                match explorer_utxos
                    .iter()
                    .find(|explorer_utxo| explorer_utxo.outpoint == vtxo_outpoint.outpoint)
                {
                    // Include VTXOs that have been confirmed on the blockchain, but whose
                    // exit path is still _inactive_.
                    Some(ExplorerUtxo {
                        confirmation_blocktime: Some(confirmation_blocktime),
                        ..
                    }) if !vtxo.can_be_claimed_unilaterally_by_owner(
                        now.as_duration().try_into().map_err(Error::ad_hoc)?,
                        std::time::Duration::from_secs(*confirmation_blocktime),
                    ) =>
                    {
                        vtxo_outpoints.push(vtxo_outpoint);
                    }
                    // The VTXO has not been confirmed on the blockchain yet. Therefore, it
                    // cannot have expired.
                    _ => {
                        vtxo_outpoints.push(vtxo_outpoint);
                    }
                }
            }

            spendable.push((vtxo_outpoints, vtxo));
        }

        Ok(spendable)
    }

    pub async fn offchain_balance(&self) -> Result<OffChainBalance, Error> {
        let list = self.spendable_vtxos().await?;
        let sum =
            list.iter()
                .flat_map(|(vtxos, _)| vtxos)
                .fold(OffChainBalance::default(), |acc, x| match x.is_pending {
                    true => OffChainBalance {
                        pending: acc.pending + x.amount,
                        ..acc
                    },
                    false => OffChainBalance {
                        confirmed: acc.confirmed + x.amount,
                        ..acc
                    },
                });

        Ok(sum)
    }

    pub async fn transaction_history(&self) -> Result<Vec<ArkTransaction>, Error> {
        let mut boarding_transactions = Vec::new();
        let mut boarding_round_transactions = Vec::new();

        let boarding_addresses = self.get_boarding_addresses()?;
        for boarding_address in boarding_addresses.iter() {
            let outpoints = self.blockchain().find_outpoints(boarding_address).await?;

            for ExplorerUtxo {
                outpoint,
                amount,
                confirmation_blocktime,
                ..
            } in outpoints.iter()
            {
                let confirmed_at = confirmation_blocktime.map(|t| t as i64);

                boarding_transactions.push(ArkTransaction::Boarding {
                    txid: outpoint.txid,
                    amount: *amount,
                    confirmed_at,
                });

                let status = self
                    .blockchain()
                    .get_output_status(&outpoint.txid, outpoint.vout)
                    .await?;

                if let Some(spend_txid) = status.spend_txid {
                    boarding_round_transactions.push(spend_txid);
                }
            }
        }

        let vtxos = self.list_vtxos().await?;

        let incoming_transactions = generate_incoming_vtxo_transaction_history(
            &vtxos.spent,
            &vtxos.spendable,
            &boarding_round_transactions,
        )?;

        let outgoing_transactions =
            generate_outgoing_vtxo_transaction_history(&vtxos.spent, &vtxos.spendable)?;

        let mut txs = [
            boarding_transactions,
            incoming_transactions,
            outgoing_transactions,
        ]
        .concat();

        txs.sort_by_key(|a| a.created_at());

        Ok(txs)
    }

    fn network_client(&self) -> ark_grpc::Client {
        self.inner.network_client.clone()
    }

    fn kp(&self) -> &Keypair {
        &self.inner.kp
    }

    fn secp(&self) -> &Secp256k1<All> {
        &self.inner.secp
    }

    fn blockchain(&self) -> &B {
        &self.inner.blockchain
    }
}
