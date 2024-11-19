use bitcoin::opcodes;
use bitcoin::secp256k1;
use bitcoin::taproot;
use bitcoin::taproot::LeafVersion;
use bitcoin::Address;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use miniscript::ToPublicKey;

#[derive(Clone, Debug)]
pub struct BoardingAddress {
    pub asp: secp256k1::PublicKey,
    pub owner: secp256k1::PublicKey,
    pub address: Address,
    pub descriptor: miniscript::descriptor::Tr<XOnlyPublicKey>,
    pub ark_descriptor: String,
}

impl BoardingAddress {
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
