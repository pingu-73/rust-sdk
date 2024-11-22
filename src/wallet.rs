use crate::boarding_output::BoardingOutput;
use crate::error::Error;
use bitcoin::{Network, XOnlyPublicKey};

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
