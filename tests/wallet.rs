use ark_rs::boarding_output::BoardingOutput;
use ark_rs::error::Error;
use ark_rs::wallet::{BoardingWallet, OnchainWallet};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::All;
use bitcoin::{Address, Amount, Network, XOnlyPublicKey};

#[derive(Clone)]
pub struct Wallet {
    kp: Keypair,
    secp: Secp256k1<All>,
}

impl Wallet {
    pub fn new(kp: Keypair, secp: Secp256k1<All>) -> Self {
        Self { kp, secp }
    }
}

impl OnchainWallet for Wallet {
    fn get_onchain_address(&self, network: Network) -> Result<Address, Error> {
        let pk = self.kp.public_key();
        let pk = bitcoin::key::CompressedPublicKey(pk);
        let address = Address::p2wpkh(&pk, network);

        Ok(address)
    }

    fn sync(&self) -> Result<(), Error> {
        Ok(())
    }

    fn balance(&self) -> Result<Amount, Error> {
        Ok(Amount::ZERO)
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
