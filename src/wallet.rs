use crate::boarding_output::BoardingOutput;
use crate::error::Error;
use bitcoin::{Address, Amount, Network, XOnlyPublicKey};

pub trait BoardingWallet {
    fn get_boarding_address(
        &self,
        asp_pubkey: XOnlyPublicKey,
        exit_delay: u32,
        descriptor_template: String,
        network: Network,
    ) -> Result<BoardingOutput, Error>;

    fn get_boarding_addresses(
        &self,
        asp_pubkey: XOnlyPublicKey,
        exit_delay: u32,
        descriptor_template: String,
        network: Network,
    ) -> Result<Vec<BoardingOutput>, Error>;
}

pub trait OnchainWallet {
    fn get_onchain_address(&self, network: Network) -> Result<Address, Error>;

    fn sync(&self) -> Result<(), Error>;

    fn balance(&self) -> Result<Amount, Error>;
}
