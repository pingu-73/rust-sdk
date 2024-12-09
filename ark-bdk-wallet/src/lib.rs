use anyhow::Result;
use ark_rs::boarding_output::BoardingOutput;
use ark_rs::error::Error;
use ark_rs::error::ErrorContext;
use ark_rs::wallet::Balance;
use ark_rs::wallet::BoardingWallet;
use ark_rs::wallet::OnchainWallet;
use ark_rs::wallet::Persistence;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::KeychainKind;
use bdk_wallet::SignOptions;
use bdk_wallet::TxOrdering;
use bdk_wallet::Wallet as BdkWallet;
use bitcoin::bip32::Xpriv;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::Message;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::FeeRate;
use bitcoin::Network;
use bitcoin::Psbt;
use bitcoin::Transaction;
use bitcoin::XOnlyPublicKey;
use std::collections::BTreeSet;
use std::io::Write;

pub struct Wallet<DB>
where
    DB: Persistence,
{
    kp: Keypair,
    secp: Secp256k1<All>,
    inner: BdkWallet,
    client: esplora_client::AsyncClient,
    db: DB,
}

impl<DB> Wallet<DB>
where
    DB: Persistence,
{
    pub fn new(
        kp: Keypair,
        secp: Secp256k1<All>,
        network: Network,
        esplora_url: &str,
        db: DB,
    ) -> Result<Self> {
        let key = kp.secret_key();
        let xprv = Xpriv::new_master(network, key.as_ref())?;
        let external = bdk_wallet::template::Bip84(xprv, KeychainKind::External);
        let change = bdk_wallet::template::Bip84(xprv, KeychainKind::Internal);
        let wallet = BdkWallet::create(external, change)
            .network(network)
            .create_wallet_no_persist()?;

        let client = esplora_client::Builder::new(esplora_url).build_async()?;

        Ok(Self {
            kp,
            secp,
            inner: wallet,
            client,
            db,
        })
    }
}

impl<DB> OnchainWallet for Wallet<DB>
where
    DB: Persistence + Send + Sync,
{
    fn get_onchain_address(&mut self) -> Result<Address, Error> {
        let info = self.inner.next_unused_address(KeychainKind::External);

        Ok(info.address)
    }

    async fn sync(&mut self) -> Result<(), Error> {
        let request = self.inner.start_full_scan().inspect({
            let mut stdout = std::io::stdout();
            let mut once = BTreeSet::<KeychainKind>::new();
            move |keychain, spk_i, _| {
                if once.insert(keychain) {
                    tracing::trace!(?keychain, "Scanning keychain");
                }
                tracing::trace!(" {:<3}", spk_i);
                stdout.flush().expect("must flush")
            }
        });

        let now = std::time::UNIX_EPOCH
            .elapsed()
            .map_err(Error::wallet)?
            .as_secs();

        // TODO: Use smarter constants or make it configurable.
        let update = self
            .client
            .full_scan(request, 5, 5)
            .await
            .map_err(Error::wallet)
            .context("Failed syncing wallet")?;
        self.inner
            .apply_update_at(update, Some(now))
            .map_err(Error::wallet)?;

        Ok(())
    }

    fn balance(&self) -> Result<Balance, Error> {
        let balance = self.inner.balance();

        Ok(Balance {
            immature: balance.immature,
            trusted_pending: balance.trusted_pending,
            untrusted_pending: balance.untrusted_pending,
            confirmed: balance.confirmed,
        })
    }

    fn prepare_send_to_address(
        &mut self,
        address: Address,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> Result<Psbt, Error> {
        let mut b = self.inner.build_tx();
        b.ordering(TxOrdering::Untouched);
        b.add_recipient(address.script_pubkey(), amount);
        b.fee_rate(fee_rate);

        let psbt = b.finish().map_err(Error::wallet)?;

        Ok(psbt)
    }

    async fn broadcast_tx(&self, tx: &Transaction) -> Result<(), Error> {
        self.client.broadcast(tx).await.map_err(Error::wallet)?;

        Ok(())
    }

    fn sign(&self, psbt: &mut Psbt, sign_options: SignOptions) -> Result<bool, Error> {
        let finalized = self.inner.sign(psbt, sign_options).map_err(Error::wallet)?;

        Ok(finalized)
    }
}

impl<DB> BoardingWallet for Wallet<DB>
where
    DB: Persistence,
{
    fn new_boarding_address(
        &mut self,
        asp_pubkey: XOnlyPublicKey,
        exit_delay: bitcoin::Sequence,
        descriptor_template: &str,
        network: Network,
    ) -> Result<BoardingOutput, Error> {
        let sk = self.kp.secret_key();
        let (owner_pk, _) = sk.public_key(&self.secp).x_only_public_key();

        let address = BoardingOutput::new(
            &self.secp,
            asp_pubkey,
            owner_pk,
            descriptor_template,
            exit_delay,
            network,
        );

        self.db
            .save_boarding_address(sk, address.clone())
            .context("Failed saving boarding address")?;

        Ok(address)
    }

    fn get_boarding_addresses(&self) -> Result<Vec<BoardingOutput>, Error> {
        self.db.load_boarding_addresses()
    }

    fn sign_boarding_address(
        &self,
        boarding_address: &BoardingOutput,
        msg: &Message,
    ) -> Result<(Signature, XOnlyPublicKey), Error> {
        let key = self
            .db
            .sk_for_boarding_address(boarding_address)
            .context("Failed retrieving secret key for boarding address")?;

        let sig = self
            .secp
            .sign_schnorr_no_aux_rand(msg, &key.keypair(&self.secp));

        let pk = key.x_only_public_key(&self.secp).0;

        Ok((sig, pk))
    }
}
