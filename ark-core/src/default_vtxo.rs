use crate::ark_address::ArkAddress;
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

const DEFAULT_VTXO_DESCRIPTOR_TEMPLATE: &str =
    "tr(UNSPENDABLE_KEY,{and(pk(USER),pk(SERVER)),and(older(TIMEOUT),pk(USER))})";

/// All the information needed to _spend_ a default VTXO.
#[derive(Debug, Clone)]
pub struct DefaultVtxo {
    server: XOnlyPublicKey,
    owner: XOnlyPublicKey,
    spend_info: TaprootSpendInfo,
    ark_descriptor: String,
    address: Address,
    exit_delay: bitcoin::Sequence,
    exit_delay_seconds: u64,
    network: Network,
}

impl DefaultVtxo {
    /// 64 bytes per pubkey. In the default VTXO we have 2 pubkeys
    pub const FORFEIT_WITNESS_SIZE: usize = 64 * 2;

    /// Build a default VTXO.
    pub fn new<C>(
        secp: &Secp256k1<C>,
        server: XOnlyPublicKey,
        owner: XOnlyPublicKey,
        exit_delay: bitcoin::Sequence,
        network: Network,
    ) -> Self
    where
        C: Verification,
    {
        let unspendable_key: PublicKey = UNSPENDABLE_KEY.parse().expect("valid key");
        let (unspendable_key, _) = unspendable_key.inner.x_only_public_key();

        let forfeit_script = multisig_script(server, owner);
        let redeem_script = csv_sig_script(exit_delay, owner);

        let spend_info = TaprootBuilder::new()
            .add_leaf(1, forfeit_script)
            .expect("valid forfeit leaf")
            .add_leaf(1, redeem_script)
            .expect("valid redeem leaf")
            .finalize(secp, unspendable_key)
            .expect("can be finalized");

        let exit_delay_seconds = match exit_delay.to_relative_lock_time() {
            Some(relative::LockTime::Time(time)) => time.value() * 512,
            _ => unreachable!("default VTXO redeem script must use relative lock time in seconds"),
        };
        let ark_descriptor = DEFAULT_VTXO_DESCRIPTOR_TEMPLATE
            .replace("UNSPENDABLE_KEY", unspendable_key.to_string().as_str())
            .replace("USER", owner.to_string().as_str())
            .replace("SERVER", server.to_string().as_str())
            .replace("TIMEOUT", exit_delay_seconds.to_string().as_str());

        let script_pubkey = tr_script_pubkey(&spend_info);
        let address = Address::from_script(&script_pubkey, network).expect("valid script");

        Self {
            server,
            owner,
            spend_info,
            ark_descriptor,
            address,
            exit_delay,
            exit_delay_seconds: exit_delay_seconds as u64,
            network,
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

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn exit_delay(&self) -> bitcoin::Sequence {
        self.exit_delay
    }

    pub fn exit_delay_duration(&self) -> Duration {
        Duration::from_secs(self.exit_delay_seconds)
    }

    pub fn to_ark_address(&self) -> ArkAddress {
        let vtxo_tap_key = self.spend_info.output_key();
        ArkAddress::new(self.network, self.server, vtxo_tap_key)
    }

    /// The spend info for the forfeit branch of a default VTXO.
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

    /// The spend info for the exit branch of a default VTXO.
    pub fn exit_spend_info(&self) -> (ScriptBuf, taproot::ControlBlock) {
        let exit_script = self.exit_script();

        let control_block = self
            .spend_info
            .control_block(&(exit_script.clone(), LeafVersion::TapScript))
            .expect("exit script");

        (exit_script, control_block)
    }

    pub fn tapscripts(&self) -> Vec<ScriptBuf> {
        let (exit_script, _) = self.exit_spend_info();
        let (forfeit_script, _) = self.forfeit_spend_info();

        vec![exit_script, forfeit_script]
    }

    /// Whether the VTXO can be claimed unilaterally by the owner or not, given the
    /// `confirmation_blocktime` of the transaction that included this VTXO as an output.
    pub fn can_be_claimed_unilaterally_by_owner(
        &self,
        now: Duration,
        confirmation_blocktime: Duration,
    ) -> bool {
        let exit_path_time = confirmation_blocktime + self.exit_delay_duration();

        now > exit_path_time
    }

    fn forfeit_script(&self) -> ScriptBuf {
        multisig_script(self.server, self.owner)
    }

    fn exit_script(&self) -> ScriptBuf {
        csv_sig_script(self.exit_delay, self.owner)
    }
}
