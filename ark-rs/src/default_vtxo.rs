use crate::script::csv_sig_script;
use crate::script::multisig_script;
use crate::script::tr_script_pubkey;
use crate::UNSPENDABLE_KEY;
use bitcoin::key::PublicKey;
use bitcoin::key::Secp256k1;
use bitcoin::key::Verification;
use bitcoin::relative::LockTime;
use bitcoin::taproot;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::Address;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;

const DEFAULT_VTXO_DESCRIPTOR_TEMPLATE: &str =
    "tr(UNSPENDABLE_KEY,{and(pk(USER),pk(ASP)),and(older(TIMEOUT),pk(USER))})";

#[derive(Debug, Clone)]
pub struct DefaultVtxo {
    asp: XOnlyPublicKey,
    owner: XOnlyPublicKey,
    spend_info: TaprootSpendInfo,
    ark_descriptor: String,
    address: Address,
}

impl DefaultVtxo {
    pub fn new<C>(
        secp: &Secp256k1<C>,
        asp: XOnlyPublicKey,
        owner: XOnlyPublicKey,
        exit_delay: bitcoin::Sequence,
        network: Network,
    ) -> Self
    where
        C: Verification,
    {
        let unspendable_key: PublicKey = UNSPENDABLE_KEY.parse().expect("valid key");
        let (unspendable_key, _) = unspendable_key.inner.x_only_public_key();

        let forfeit_script = multisig_script(asp, owner);
        let redeem_script = csv_sig_script(exit_delay, owner);

        let spend_info = TaprootBuilder::new()
            .add_leaf(1, forfeit_script)
            .expect("valid forfeit leaf")
            .add_leaf(1, redeem_script)
            .expect("valid redeem leaf")
            .finalize(secp, unspendable_key)
            .expect("can be finalized");

        let exit_delay_seconds = match exit_delay.to_relative_lock_time() {
            Some(LockTime::Time(time)) => time.value() * 512,
            _ => unreachable!("default VTXO redeem script must use relative lock time in seconds"),
        };
        let ark_descriptor = DEFAULT_VTXO_DESCRIPTOR_TEMPLATE
            .replace("UNSPENDABLE_KEY", unspendable_key.to_string().as_str())
            .replace("USER", owner.to_string().as_str())
            .replace("ASP", asp.to_string().as_str())
            .replace("TIMEOUT", exit_delay_seconds.to_string().as_str());

        let script_pubkey = tr_script_pubkey(&spend_info);
        let address = Address::from_script(&script_pubkey, network).expect("valid script");

        Self {
            asp,
            owner,
            spend_info,
            ark_descriptor,
            address,
        }
    }

    pub fn spend_info(&self) -> &TaprootSpendInfo {
        &self.spend_info
    }

    pub fn ark_descriptor(&self) -> &str {
        &self.ark_descriptor
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address.script_pubkey()
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

    fn forfeit_script(&self) -> ScriptBuf {
        multisig_script(self.asp, self.owner)
    }
}
