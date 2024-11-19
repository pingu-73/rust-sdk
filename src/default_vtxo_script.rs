use crate::error::Error;
use crate::UNSPENDABLE_KEY;
use bitcoin::key::PublicKey;
use bitcoin::opcodes;
use bitcoin::taproot;
use bitcoin::taproot::LeafVersion;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use miniscript::translate_hash_fail;
use miniscript::Descriptor;
use miniscript::ToPublicKey;
use miniscript::TranslatePk;
use miniscript::Translator;
use std::collections::HashMap;
use std::str::FromStr;

/// The Miniscript descriptor used for the default VTXO.
///
/// We expect the ASP to provide this, but at the moment the ASP does not quite speak Miniscript.
///
/// We use `USER_0` and `USER_1` for the same user key, because `rust-miniscript` does not allow
/// repeating identifiers.
const DEFAULT_VTXO_DESCRIPTOR_TEMPLATE_MINISCRIPT: &str =
    "tr(UNSPENDABLE_KEY,{and_v(v:pk(ASP),pk(USER_1)),and_v(v:older(TIMEOUT),pk(USER_0))})";

/// tr(unspendable, { and(pk(user), pk(asp)), and(older(timeout), pk(user)) })
const DEFAULT_VTXO_DESCRIPTOR_TEMPLATE: &str =
    "tr(UNSPENDABLE_KEY,{and(pk(USER),pk(ASP)),and(older(TIMEOUT),pk(USER))})";

#[derive(Debug, Clone)]
pub struct DefaultVtxoScript {
    pub asp: XOnlyPublicKey,
    pub owner: XOnlyPublicKey,
    pub exit_delay: u64,
    pub descriptor: miniscript::descriptor::Tr<XOnlyPublicKey>,
    pub ark_descriptor: String,
}

impl DefaultVtxoScript {
    pub fn new(asp: XOnlyPublicKey, owner: XOnlyPublicKey, exit_delay: u64) -> Result<Self, Error> {
        let vtxo_descriptor = {
            let exit_delay =
                bitcoin::Sequence::from_seconds_floor(exit_delay as u32).expect("valid");
            let exit_delay = exit_delay.to_relative_lock_time().expect("relative");

            DEFAULT_VTXO_DESCRIPTOR_TEMPLATE_MINISCRIPT.replace(
                "TIMEOUT",
                exit_delay.to_consensus_u32().to_string().as_str(),
            )
        };

        let descriptor = Descriptor::<String>::from_str(&vtxo_descriptor).unwrap();

        debug_assert!(descriptor.sanity_check().is_ok());

        let unspendable_key: PublicKey = UNSPENDABLE_KEY.parse().unwrap();
        let unspendable_key = unspendable_key.to_x_only_pubkey();

        let mut pk_map = HashMap::new();

        pk_map.insert("UNSPENDABLE_KEY".to_string(), unspendable_key);
        pk_map.insert("USER_0".to_string(), owner);
        pk_map.insert("USER_1".to_string(), owner);
        pk_map.insert("ASP".to_string(), asp);

        let mut t = StrPkTranslator { pk_map };

        let real_desc = descriptor.translate_pk(&mut t).unwrap();

        let tr = match real_desc {
            Descriptor::Tr(tr) => tr,
            _ => unreachable!("Descriptor must be taproot"),
        };

        let ark_descriptor = DEFAULT_VTXO_DESCRIPTOR_TEMPLATE
            .replace("UNSPENDABLE_KEY", unspendable_key.to_string().as_str())
            .replace("USER", owner.to_string().as_str())
            .replace("ASP", asp.to_string().as_str())
            .replace("TIMEOUT", exit_delay.to_string().as_str());

        Ok(Self {
            asp,
            owner,
            exit_delay,
            descriptor: tr,
            ark_descriptor,
        })
    }

    pub fn forfeit_spend_info(&self) -> (ScriptBuf, taproot::ControlBlock) {
        let asp = self.asp.to_x_only_pubkey();
        let owner = self.owner.to_x_only_pubkey();

        // It's kind of rubbish that we need to reconstruct the script manually to get the
        // `ControlBlock`. It would be nicer to just get the `ControlBlock` for the left leaf and
        // the right leaf, knowing which one is which.
        let script = bitcoin::ScriptBuf::builder()
            .push_x_only_key(&asp)
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_x_only_key(&owner)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        let control_block = self
            .descriptor
            .spend_info()
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("control block");

        (script, control_block)
    }
}

pub struct StrPkTranslator {
    pub pk_map: HashMap<String, XOnlyPublicKey>,
}

impl Translator<String, XOnlyPublicKey, ()> for StrPkTranslator {
    fn pk(&mut self, pk: &String) -> Result<XOnlyPublicKey, ()> {
        self.pk_map.get(pk).copied().ok_or(())
    }

    // We don't need to implement these methods as we are not using them in the policy.
    // Fail if we encounter any hash fragments. See also translate_hash_clone! macro.
    translate_hash_fail!(String, XOnlyPublicKey, ());
}
