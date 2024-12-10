use crate::script::csv_sig_script;
use crate::script::multisig_script;
use crate::script::tr_script_pubkey;
use crate::UNSPENDABLE_KEY;
use bitcoin::key::PublicKey;
use bitcoin::key::Secp256k1;
use bitcoin::key::Verification;
use bitcoin::relative;
use bitcoin::taproot;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::Address;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
pub struct BoardingOutput {
    asp: XOnlyPublicKey,
    owner: XOnlyPublicKey,
    spend_info: TaprootSpendInfo,
    address: Address,
    ark_descriptor: String,
    exit_delay: bitcoin::Sequence,
}

impl BoardingOutput {
    pub fn new<C>(
        secp: &Secp256k1<C>,
        asp: XOnlyPublicKey,
        owner: XOnlyPublicKey,
        boarding_descriptor_template: &str,
        exit_delay: bitcoin::Sequence,
        network: Network,
    ) -> Self
    where
        C: Verification,
    {
        let unspendable_key: PublicKey = UNSPENDABLE_KEY.parse().expect("valid key");
        let (unspendable_key, _) = unspendable_key.inner.x_only_public_key();

        let multisig_script = multisig_script(asp, owner);
        let exit_script = csv_sig_script(exit_delay, owner);

        let spend_info = TaprootBuilder::new()
            .add_leaf(1, multisig_script)
            .expect("valid multisig leaf")
            .add_leaf(1, exit_script)
            .expect("valid exit leaf")
            .finalize(secp, unspendable_key)
            .expect("can be finalized");

        let ark_descriptor =
            boarding_descriptor_template.replace("USER", owner.to_string().as_str());

        let script_pubkey = tr_script_pubkey(&spend_info);
        let address = Address::from_script(&script_pubkey, network).expect("valid script");

        Self {
            asp,
            owner,
            spend_info,
            address,
            ark_descriptor,
            exit_delay,
        }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn ark_descriptor(&self) -> &str {
        &self.ark_descriptor
    }

    pub fn forfeit_spend_info(&self) -> (ScriptBuf, taproot::ControlBlock) {
        // It's kind of rubbish that we need to reconstruct the script every time we want a
        // `ControlBlock`. It would be nicer to just get the `ControlBlock` for the left leaf and
        // the right leaf, knowing which one is which.

        let forfeit_script = self.forfeit_script();

        let control_block = self
            .spend_info
            .control_block(&(forfeit_script.clone(), LeafVersion::TapScript))
            .expect("forfeit script");

        (forfeit_script, control_block)
    }

    pub fn exit_spend_info(&self) -> (ScriptBuf, taproot::ControlBlock) {
        let exit_script = self.exit_script();

        let control_block = self
            .spend_info
            .control_block(&(exit_script.clone(), LeafVersion::TapScript))
            .expect("exit script");

        (exit_script, control_block)
    }

    pub fn exit_delay(&self) -> bitcoin::Sequence {
        self.exit_delay
    }

    pub fn exit_delay_duration(&self) -> Duration {
        let exit_delay = self
            .exit_delay
            .to_relative_lock_time()
            .expect("relative lock time");

        match exit_delay {
            relative::LockTime::Time(time) => Duration::from_secs(time.value() as u64 * 512),
            relative::LockTime::Blocks(_) => {
                unreachable!("Only seconds timelock is supported");
            }
        }
    }

    fn forfeit_script(&self) -> ScriptBuf {
        multisig_script(self.asp, self.owner)
    }

    fn exit_script(&self) -> ScriptBuf {
        csv_sig_script(self.exit_delay, self.owner)
    }
}
