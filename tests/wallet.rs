use ark_rs::boarding_output::BoardingOutput;
use ark_rs::error::Error;
use ark_rs::wallet::Balance;
use ark_rs::wallet::BoardingWallet;
use ark_rs::wallet::OnchainWallet;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::KeychainKind;
use bdk_wallet::Wallet as BdkWallet;
use bitcoin::bip32::Xpriv;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::Address;
use bitcoin::Network;
use bitcoin::XOnlyPublicKey;
use std::collections::BTreeSet;
use std::io::Write;

pub struct Wallet {
    kp: Keypair,
    secp: Secp256k1<All>,
    inner: BdkWallet,
    client: esplora_client::AsyncClient,
}

impl Wallet {
    pub fn new(kp: Keypair, secp: Secp256k1<All>, network: Network, esplora_url: &str) -> Self {
        let key = kp.secret_key();
        let xprv = Xpriv::new_master(network, key.as_ref()).unwrap();
        let external = bdk_wallet::template::Bip84(xprv, KeychainKind::External);
        let change = bdk_wallet::template::Bip84(xprv, KeychainKind::Internal);
        let wallet = BdkWallet::create(external, change)
            .network(network)
            .create_wallet_no_persist()
            .unwrap();

        let client = esplora_client::Builder::new(esplora_url)
            .build_async()
            .unwrap();

        Self {
            kp,
            secp,
            inner: wallet,
            client,
        }
    }
}

impl OnchainWallet for Wallet {
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
                    print!("\nScanning keychain [{:?}]", keychain);
                }
                print!(" {:<3}", spk_i);
                stdout.flush().expect("must flush")
            }
        });

        // TODO: use smarter constants or make it configurable
        let update = self.client.full_scan(request, 5, 5).await.unwrap();

        self.inner.apply_update(update).unwrap();

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
}

impl BoardingWallet for Wallet {
    fn get_boarding_address(
        &self,
        asp_pubkey: XOnlyPublicKey,
        exit_delay: u32,
        descriptor_template: String,
        network: Network,
    ) -> Result<BoardingOutput, Error> {
        let (owner_pk, _) = self.kp.public_key().x_only_public_key();

        let address = BoardingOutput::new(
            &self.secp,
            asp_pubkey,
            owner_pk,
            descriptor_template,
            exit_delay,
            network,
        )?;

        Ok(address)
    }

    fn get_boarding_addresses(
        &self,
        asp_pubkey: XOnlyPublicKey,
        exit_delay: u32,
        descriptor_template: String,
        network: Network,
    ) -> Result<Vec<BoardingOutput>, Error> {
        let boarding_output =
            self.get_boarding_address(asp_pubkey, exit_delay, descriptor_template, network)?;
        Ok(vec![boarding_output])
    }
}
