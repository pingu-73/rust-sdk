//! Messages exchanged between the client and the Ark server.

use crate::ark_address::ArkAddress;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::ScriptBuf;
use bitcoin::Txid;

#[derive(Clone, Debug)]
pub struct RoundInput {
    outpoint: OutPoint,
    /// All the scripts hidden in the leaves of the Taproot tree for this input.
    tapscripts: Vec<ScriptBuf>,
}

impl RoundInput {
    pub fn new(outpoint: OutPoint, tapscripts: Vec<ScriptBuf>) -> Self {
        Self {
            outpoint,
            tapscripts,
        }
    }

    pub fn outpoint(&self) -> OutPoint {
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
    pub outpoint: OutPoint,
    pub spent: bool,
    pub round_txid: Txid,
    pub spent_by: Option<Txid>,
    pub expire_at: i64,
    pub swept: bool,
    pub is_pending: bool,
    /// The redeem transaction which has this [`VtxoOutPoint`] as an output. The txid matches the
    /// TXID of the `outpoint` field.
    pub redeem_tx: Option<Psbt>,
    pub amount: Amount,
    pub pubkey: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct Info {
    pub pk: PublicKey,
    pub round_lifetime: bitcoin::Sequence,
    pub unilateral_exit_delay: bitcoin::Sequence,
    pub round_interval: i64,
    pub network: Network,
    pub dust: Amount,
    pub boarding_descriptor_template: String,
    pub vtxo_descriptor_templates: Vec<String>,
    pub forfeit_address: bitcoin::Address,
}

#[derive(Clone, Debug)]
pub struct ListVtxo {
    pub spent: Vec<VtxoOutPoint>,
    pub spendable: Vec<VtxoOutPoint>,
}

#[derive(Debug, Clone)]
pub struct RoundFinalizationEvent {
    pub id: String,
    pub round_tx: Psbt,
    pub vtxo_tree: Option<Tree>,
    pub connectors: Vec<Psbt>,
    pub min_relay_fee_rate: i64,
}

#[derive(Debug, Clone)]
pub struct RoundFinalizedEvent {
    pub id: String,
    pub round_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct RoundFailedEvent {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RoundSigningEvent {
    pub id: String,
    pub cosigners_pubkeys: Vec<PublicKey>,
    pub unsigned_vtxo_tree: Option<Tree>,
    pub unsigned_round_tx: Psbt,
}

#[derive(Debug, Clone)]
pub struct RoundSigningNoncesGeneratedEvent {
    pub id: String,
    pub tree_nonces: Vec<Vec<zkp::MusigPubNonce>>,
}

#[derive(Debug, Clone)]
pub enum RoundStreamEvent {
    RoundFinalization(RoundFinalizationEvent),
    RoundFinalized(RoundFinalizedEvent),
    RoundFailed(RoundFailedEvent),
    RoundSigning(RoundSigningEvent),
    RoundSigningNoncesGenerated(RoundSigningNoncesGeneratedEvent),
}

pub enum TransactionEvent {
    Round(RoundTransaction),
    Redeem(RedeemTransaction),
}

pub struct RedeemTransaction {
    pub txid: Txid,
    pub spent_vtxos: Vec<OutPoint>,
    pub spendable_vtxos: Vec<VtxoOutPoint>,
}

pub struct RoundTransaction {
    pub txid: Txid,
    pub spent_vtxos: Vec<OutPoint>,
    pub spendable_vtxos: Vec<VtxoOutPoint>,
    pub claimed_boarding_utxos: Vec<OutPoint>,
}
