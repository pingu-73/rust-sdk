use bitcoin::opcodes::all::*;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TapLeaf;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;

/// The script of an _internal_ node of the VTXO tree. By internal node we mean a non-leaf node.
///
/// This script allows the ASP to sweep the entire output after `round_lifetime_seconds` have passed
/// from the time the output was included in a block.
pub struct VtxoTreeInternalNodeScript {
    script: ScriptBuf,
}

impl VtxoTreeInternalNodeScript {
    pub fn new(round_lifetime_seconds: u32, asp: XOnlyPublicKey) -> Self {
        let csv = bitcoin::Sequence::from_seconds_ceil(round_lifetime_seconds).unwrap();

        let script = bitcoin::ScriptBuf::builder()
            .push_int(csv.to_consensus_u32() as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&asp)
            .push_opcode(OP_CHECKSIG)
            .into_script();

        Self { script }
    }

    /// Construct a [`TapLeaf`] based on the script of the internal node.
    ///
    /// # Clarification
    ///
    /// There are two completely different trees at play here:
    ///
    /// - The VTXO tree.
    /// - The Taproot tree of the internal node of the VTXO tree.
    pub fn leaf(&self) -> TapLeaf {
        TapLeaf::Script(self.script.clone(), LeafVersion::TapScript)
    }
}
