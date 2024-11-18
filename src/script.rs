use crate::error::Error;
use bitcoin::opcodes;
use bitcoin::opcodes::all::OP_CSV;
use bitcoin::opcodes::all::OP_VERIFY;
use bitcoin::secp256k1;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TapLeaf;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
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

// TODO: Convert into `CsvSigClosure::parse` function.
pub fn extract_sequence_from_csv_sig_closure(script: &ScriptBuf) -> Result<Sequence, Error> {
    let csv_index = script
        .to_bytes()
        .windows(2)
        .position(|window| *window == [OP_CSV.to_u8(), OP_VERIFY.to_u8()])
        .unwrap();

    let before_csv = &script.to_bytes()[..csv_index];

    // It is either `OP_PUSHNUM_X` (a single byte) or `OP_PUSH_BYTES_X BYTES` (more than one
    // byte).
    let sequence = if before_csv.len() > 1 {
        &before_csv[1..]
    } else {
        before_csv
    };

    let mut sequence = sequence.to_vec();
    sequence.reverse();

    let mut buffer = [0u8; 4];
    let input_len = sequence.len();
    let start_index = 4 - input_len; // calculate how many spaces to leave at the front

    buffer[start_index..].copy_from_slice(&sequence);

    let sequence = u32::from_be_bytes(buffer);

    let sequence = Sequence::from_consensus(sequence);

    Ok(sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::XOnlyPublicKey;
    use std::str::FromStr;

    #[test]
    fn parse_csv_sig_closure() {
        let timeout = 4820384;
        let csv = bitcoin::Sequence::from_seconds_ceil(timeout).unwrap();

        let pk = XOnlyPublicKey::from_str(
            "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();

        let script = bitcoin::ScriptBuf::builder()
            .push_int(csv.to_consensus_u32() as i64)
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_VERIFY)
            .push_x_only_key(&pk)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        let parsed = extract_sequence_from_csv_sig_closure(&script).unwrap();

        assert_eq!(parsed.to_consensus_u32(), csv.to_consensus_u32());
    }
}
