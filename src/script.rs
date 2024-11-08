use bitcoin::opcodes;
use bitcoin::secp256k1;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TapLeaf;
use miniscript::ToPublicKey;

pub struct CsvSigClosure {
    pub pk: secp256k1::PublicKey,
    pub timeout: i64,
}

impl CsvSigClosure {
    pub fn leaf(&self) -> TapLeaf {
        let csv = bitcoin::Sequence::from_seconds_ceil(self.timeout as u32).unwrap();
        let pk = self.pk.to_x_only_pubkey();

        let script = bitcoin::ScriptBuf::builder()
            .push_int(csv.to_consensus_u32() as i64)
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_VERIFY)
            .push_x_only_key(&pk)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        TapLeaf::Script(script, LeafVersion::TapScript)
    }
}
