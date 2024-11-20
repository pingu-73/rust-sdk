use crate::ark_address::ArkAddress;
use crate::asp::types::Info;
use crate::asp::types::ListVtxo;
use crate::asp::types::Vtxo;
use crate::error::Error;
use crate::generated::ark::v1::ark_service_client::ArkServiceClient;
use crate::generated::ark::v1::GetInfoRequest;
use crate::generated::ark::v1::Input;
use crate::generated::ark::v1::ListVtxosRequest;
use crate::generated::ark::v1::Outpoint;
use crate::generated::ark::v1::Output;
use crate::generated::ark::v1::PingRequest;
use crate::generated::ark::v1::RegisterInputsForNextRoundRequest;
use crate::generated::ark::v1::RegisterOutputsForNextRoundRequest;
use crate::generated::ark::v1::{AsyncPaymentInput, SubmitTreeNoncesRequest};
use crate::generated::ark::v1::{CompletePaymentRequest, SubmitTreeSignaturesRequest};
use crate::generated::ark::v1::{CreatePaymentRequest, SubmitSignedForfeitTxsRequest};
use crate::tree;
use base64::Engine;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::TapLeafHash;
use bitcoin::Txid;
use tonic::transport::Channel;

pub struct PaymentInput {
    pub forfeit_leaf_hash: TapLeafHash,
    pub outpoint: Option<OutPoint>,
    pub descriptor: String,
}

pub struct PaymentOutput {
    pub address: ArkAddress,
    pub amount: Amount,
}

pub struct RoundInputs {
    pub outpoint: Option<OutPoint>,
    pub descriptor: String,
}

pub struct RoundOutputs {
    // TODO: would be cool to have a type here which accepts ArkAddress and bitcoin::Address
    pub address: String,
    pub amount: Amount,
}

#[derive(Debug, Clone)]
pub struct PingResponse {
    pub response: Option<PingResponseType>,
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
    pub txid: String,
    pub tx: String,
    pub parent_txid: String,
}

#[derive(Debug, Clone)]
pub struct RoundFinalizationEvent {
    pub id: String,
    pub round_tx: String,
    pub vtxo_tree: Option<Tree>,
    pub connectors: Vec<String>,
    pub min_relay_fee_rate: i64,
}

#[derive(Debug, Clone)]
pub struct RoundFinalizedEvent {
    pub id: String,
    pub round_txid: String,
}

#[derive(Debug, Clone)]
pub struct RoundFailedEvent {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RoundSigningEvent {
    pub id: String,
    pub cosigners_pubkeys: Vec<String>,
    pub unsigned_vtxo_tree: Option<Tree>,
    pub unsigned_round_tx: String,
}

#[derive(Debug, Clone)]
pub struct RoundSigningNoncesGeneratedEvent {
    pub id: String,
    pub tree_nonces: String,
}

#[derive(Debug, Clone)]
pub enum PingResponseType {
    RoundFinalization(RoundFinalizationEvent),
    RoundFinalized(RoundFinalizedEvent),
    RoundFailed(RoundFailedEvent),
    RoundSigning(RoundSigningEvent),
    RoundSigningNoncesGenerated(RoundSigningNoncesGeneratedEvent),
}

#[derive(Debug, Clone)]
pub struct Client {
    url: String,
    // TODO: Make this not public and fix everything in the world. Can still expose, but via a
    // method.
    pub inner: Option<ArkServiceClient<Channel>>,
}

impl Client {
    pub fn new(url: String) -> Self {
        Self { url, inner: None }
    }

    pub async fn connect(&mut self) -> Result<(), Error> {
        let client = ArkServiceClient::connect(self.url.clone()).await.unwrap();

        self.inner = Some(client);
        Ok(())
    }

    pub async fn get_info(&self) -> Result<Info, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let response = inner.get_info(GetInfoRequest {}).await.unwrap();

        response.into_inner().try_into()
    }

    pub async fn list_vtxos(&self, address: ArkAddress) -> Result<ListVtxo, Error> {
        let address = address.encode()?;

        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let response = inner
            .list_vtxos(ListVtxosRequest { address })
            .await
            .unwrap();
        let spent: Result<Vec<Vtxo>, Error> = response
            .get_ref()
            .spendable_vtxos
            .iter()
            .map(Vtxo::try_from)
            .collect();
        let spendable: Result<Vec<Vtxo>, Error> = response
            .get_ref()
            .spendable_vtxos
            .iter()
            .map(Vtxo::try_from)
            .collect();

        Ok(ListVtxo {
            spent: spent?,
            spendable: spendable?,
        })
    }

    pub async fn register_inputs_for_next_round(
        &self,
        ephemeral_key: PublicKey,
        inputs: Vec<RoundInputs>,
    ) -> Result<String, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let inputs = inputs
            .iter()
            .map(|input| Input {
                outpoint: input.outpoint.map(|out| Outpoint {
                    txid: out.txid.to_string(),
                    vout: out.vout,
                }),
                descriptor: input.descriptor.clone(),
            })
            .collect();

        let response = inner
            .register_inputs_for_next_round(RegisterInputsForNextRoundRequest {
                inputs,
                ephemeral_pubkey: Some(ephemeral_key.to_string()),
            })
            .await
            .unwrap();
        let response = response.into_inner();

        Ok(response.id)
    }

    pub async fn register_outputs_for_next_round(
        &self,
        round_id: String,
        outpouts: Vec<RoundOutputs>,
    ) -> Result<(), Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let outputs = outpouts
            .iter()
            .map(|out| Output {
                address: out.address.clone(),
                amount: out.amount.to_sat(),
            })
            .collect();

        inner
            .register_outputs_for_next_round(RegisterOutputsForNextRoundRequest {
                id: round_id,
                outputs,
            })
            .await
            .unwrap();

        Ok(())
    }

    pub async fn send_payment(
        &self,
        inputs: Vec<PaymentInput>,
        outputs: Vec<PaymentOutput>,
    ) -> Result<Psbt, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let inputs = inputs
            .iter()
            .map(|input| {
                // The ASP reverses this for some reason.
                let mut leaf_hash = input.forfeit_leaf_hash.to_byte_array();
                leaf_hash.reverse();

                AsyncPaymentInput {
                    input: Some(Input {
                        outpoint: input.outpoint.map(|outpoint| Outpoint {
                            txid: outpoint.txid.to_string(),
                            vout: outpoint.vout,
                        }),
                        descriptor: input.descriptor.clone(),
                    }),
                    forfeit_leaf_hash: leaf_hash.to_lower_hex_string(),
                }
            })
            .collect();

        let outputs = outputs
            .iter()
            .map(|output| Output {
                address: output.address.encode().unwrap(),
                amount: output.amount.to_sat(),
            })
            .collect();

        let res = inner
            .create_payment(CreatePaymentRequest { inputs, outputs })
            .await
            .unwrap();

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let signed_redeem_psbt = {
            let psbt = base64.decode(&res.into_inner().signed_redeem_tx).unwrap();

            Psbt::deserialize(&psbt).unwrap()
        };
        Ok(signed_redeem_psbt)
    }

    pub async fn complete_payment_request(&self, signed_psbt: Psbt) -> Result<Txid, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let signed_psbt_base64 = base64.encode(signed_psbt.serialize());

        let _response = inner
            .complete_payment(CompletePaymentRequest {
                signed_redeem_tx: signed_psbt_base64,
            })
            .await
            .unwrap();
        let txid = signed_psbt.unsigned_tx.compute_txid();

        Ok(txid)
    }

    pub async fn ping(&self, payment_id: String) -> Result<PingResponse, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let response = inner.ping(PingRequest { payment_id }).await.unwrap();
        let response = response.into_inner();

        Ok(response.into())
    }

    pub async fn submit_tree_nonces(
        &self,
        round_id: String,
        ephemeral_pubkey: PublicKey,
        pub_nonce_tree: Vec<Vec<zkp::MusigPubNonce>>,
    ) -> Result<(), Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let nonce_tree = tree::encode_tree(pub_nonce_tree).unwrap();

        inner
            .submit_tree_nonces(SubmitTreeNoncesRequest {
                round_id,
                pubkey: ephemeral_pubkey.to_string(),
                tree_nonces: nonce_tree.to_lower_hex_string(),
            })
            .await
            .unwrap();

        Ok(())
    }

    pub async fn submit_tree_signatures(
        &self,
        round_id: String,
        ephemeral_pubkey: zkp::PublicKey,
        partial_sig_tree: Vec<Vec<zkp::MusigPartialSignature>>,
    ) -> Result<(), Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let tree_signatures = tree::encode_tree(partial_sig_tree).unwrap();

        inner
            .submit_tree_signatures(SubmitTreeSignaturesRequest {
                round_id,
                pubkey: ephemeral_pubkey.to_string(),
                tree_signatures: tree_signatures.to_lower_hex_string(),
            })
            .await
            .unwrap();

        Ok(())
    }

    pub async fn submit_signed_forfeit_txs(
        &self,
        signed_forfeit_txs: Vec<Psbt>,
        signed_round_psbt: Psbt,
    ) -> Result<(), Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        inner
            .submit_signed_forfeit_txs(SubmitSignedForfeitTxsRequest {
                signed_forfeit_txs: signed_forfeit_txs
                    .iter()
                    .map(|psbt| base64.encode(psbt.serialize()))
                    .collect(),
                signed_round_tx: Some(base64.encode(signed_round_psbt.serialize())),
            })
            .await
            .unwrap();

        Ok(())
    }
}

impl From<crate::generated::ark::v1::PingResponse> for PingResponse {
    fn from(value: crate::generated::ark::v1::PingResponse) -> Self {
        let response = value.event.map(|event| match event {
            crate::generated::ark::v1::ping_response::Event::RoundFinalization(r) => {
                PingResponseType::RoundFinalization(RoundFinalizationEvent {
                    id: r.id,
                    round_tx: r.round_tx,
                    vtxo_tree: r.vtxo_tree.map(|tree| tree.into()),
                    connectors: r.connectors,
                    min_relay_fee_rate: r.min_relay_fee_rate,
                })
            }
            crate::generated::ark::v1::ping_response::Event::RoundFinalized(r) => {
                PingResponseType::RoundFinalized(RoundFinalizedEvent {
                    id: r.id,
                    round_txid: r.round_txid,
                })
            }
            crate::generated::ark::v1::ping_response::Event::RoundFailed(e) => {
                PingResponseType::RoundFailed(RoundFailedEvent {
                    id: e.id,
                    reason: e.reason,
                })
            }
            crate::generated::ark::v1::ping_response::Event::RoundSigning(e) => {
                PingResponseType::RoundSigning(RoundSigningEvent {
                    id: e.id,
                    cosigners_pubkeys: e.cosigners_pubkeys,
                    unsigned_vtxo_tree: e.unsigned_vtxo_tree.map(|tree| tree.into()),
                    unsigned_round_tx: e.unsigned_round_tx,
                })
            }
            crate::generated::ark::v1::ping_response::Event::RoundSigningNoncesGenerated(e) => {
                PingResponseType::RoundSigningNoncesGenerated(RoundSigningNoncesGeneratedEvent {
                    id: e.id,
                    tree_nonces: e.tree_nonces,
                })
            }
        });
        PingResponse { response }
    }
}

impl From<crate::generated::ark::v1::Tree> for Tree {
    fn from(value: crate::generated::ark::v1::Tree) -> Self {
        Tree {
            levels: value.levels.into_iter().map(|level| level.into()).collect(),
        }
    }
}

impl From<crate::generated::ark::v1::TreeLevel> for TreeLevel {
    fn from(value: crate::generated::ark::v1::TreeLevel) -> Self {
        TreeLevel {
            nodes: value.nodes.into_iter().map(|node| node.into()).collect(),
        }
    }
}

impl From<crate::generated::ark::v1::Node> for Node {
    fn from(value: crate::generated::ark::v1::Node) -> Self {
        Node {
            txid: value.txid,
            tx: value.tx,
            parent_txid: value.parent_txid,
        }
    }
}
