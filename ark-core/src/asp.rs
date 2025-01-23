use crate::ark_address::ArkAddress;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::ScriptBuf;
use bitcoin::Txid;

#[derive(Clone, Debug)]
pub struct RoundInput {
    outpoint: Option<OutPoint>,
    /// All the scripts hidden in the leaves of the Taproot tree for this input.
    tapscripts: Vec<ScriptBuf>,
}

impl RoundInput {
    pub fn new(outpoint: Option<OutPoint>, tapscripts: Vec<ScriptBuf>) -> Self {
        Self {
            outpoint,
            tapscripts,
        }
    }

    pub fn outpoint(&self) -> Option<OutPoint> {
        self.outpoint
    }

    pub fn tapscripts(&self) -> &[ScriptBuf] {
        &self.tapscripts
    }
}

#[derive(Clone, Debug)]
pub struct RoundOutput {
    address: RoundOutputAddress,
    amount: Amount,
}

impl RoundOutput {
    pub fn new_virtual(address: ArkAddress, amount: Amount) -> Self {
        Self {
            address: RoundOutputAddress::Virtual(address),
            amount,
        }
    }

    pub fn new_on_chain(address: bitcoin::Address, amount: Amount) -> Self {
        Self {
            address: RoundOutputAddress::OnChain(address),
            amount,
        }
    }

    pub fn address(&self) -> &RoundOutputAddress {
        &self.address
    }

    pub fn amount(&self) -> Amount {
        self.amount
    }
}

#[derive(Clone, Debug)]
pub enum RoundOutputAddress {
    Virtual(ArkAddress),
    OnChain(bitcoin::Address),
}

impl RoundOutputAddress {
    pub fn serialize(&self) -> String {
        match self {
            RoundOutputAddress::Virtual(address) => address.encode(),
            RoundOutputAddress::OnChain(address) => address.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Tree {
    pub levels: Vec<TreeLevel>,
}

#[derive(Debug, Clone)]
pub struct TreeLevel {
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub txid: Txid,
    pub tx: Psbt,
    pub parent_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct Round {
    pub id: String,
    pub start: i64,
    pub end: i64,
    pub round_tx: Psbt,
    pub vtxo_tree: Option<Tree>,
    pub forfeit_txs: Vec<Psbt>,
    pub connectors: Vec<Psbt>,
    pub stage: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VtxoOutPoint {
    // TODO: Is this supposed to be an `Option`?
    pub outpoint: Option<OutPoint>,
    pub spent: bool,
    pub round_txid: Txid,
    pub spent_by: String,
    pub expire_at: i64,
    pub swept: bool,
    pub is_pending: bool,
    pub redeem_tx: Option<Psbt>,
    pub amount: Amount,
    pub pubkey: String,
    pub created_at: i64,
}
