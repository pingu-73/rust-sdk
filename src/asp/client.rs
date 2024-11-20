use crate::ark_address::ArkAddress;
use crate::asp::types::Info;
use crate::asp::types::ListVtxo;
use crate::asp::types::Vtxo;
use crate::error::AspApiError;
use crate::error::Error;
use crate::generated::ark::v1::ark_service_client::ArkServiceClient;
use crate::generated::ark::v1::AsyncPaymentInput;
use crate::generated::ark::v1::CompletePaymentRequest;
use crate::generated::ark::v1::CreatePaymentRequest;
use crate::generated::ark::v1::GetEventStreamRequest;
use crate::generated::ark::v1::GetInfoRequest;
use crate::generated::ark::v1::GetRoundRequest;
use crate::generated::ark::v1::Input;
use crate::generated::ark::v1::ListVtxosRequest;
use crate::generated::ark::v1::Outpoint;
use crate::generated::ark::v1::Output;
use crate::generated::ark::v1::PingRequest;
use crate::generated::ark::v1::RegisterInputsForNextRoundRequest;
use crate::generated::ark::v1::RegisterOutputsForNextRoundRequest;
use crate::generated::ark::v1::SubmitSignedForfeitTxsRequest;
use crate::generated::ark::v1::SubmitTreeNoncesRequest;
use crate::generated::ark::v1::SubmitTreeSignaturesRequest;
use crate::tree;
use async_stream::stream;
use base64::Engine;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::TapLeafHash;
use bitcoin::Txid;
use futures::Stream;
use futures::StreamExt;
use futures::TryStreamExt;
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
pub enum RoundStreamEvent {
    RoundFinalization(RoundFinalizationEvent),
    RoundFinalized(RoundFinalizedEvent),
    RoundFailed(RoundFailedEvent),
    RoundSigning(RoundSigningEvent),
    RoundSigningNoncesGenerated(RoundSigningNoncesGeneratedEvent),
}

pub struct Round {
    pub id: String,
    pub start: i64,
    pub end: i64,
    pub round_tx: String,
    pub vtxo_tree: Option<Tree>,
    pub forfeit_txs: Vec<String>,
    pub connectors: Vec<String>,
    pub stage: i32,
}

#[derive(Debug, Clone)]
pub struct Client {
    url: String,
    inner: Option<ArkServiceClient<Channel>>,
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
                notes: Vec::new(),
            })
            .await
            .unwrap();
        let payment_id = response.into_inner().id;

        Ok(payment_id)
    }

    pub async fn register_outputs_for_next_round(
        &self,
        payment_id: String,
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
                id: payment_id,
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

    pub async fn ping(&self, payment_id: String) -> Result<(), Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        inner
            .ping(PingRequest { payment_id })
            .await
            .map_err(|e| Error::AspApi(AspApiError::Ping(e.message().to_string())))?;

        Ok(())
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

    pub async fn get_event_stream(
        &self,
    ) -> Result<impl Stream<Item = Result<RoundStreamEvent, Error>> + Unpin, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let response = inner
            .get_event_stream(GetEventStreamRequest {})
            .await
            .unwrap();
        let mut stream = response.into_inner();

        let stream = stream! {
            loop {
                match stream.try_next().await {
                    Ok(Some(event)) => match event.event {
                        None => {
                            tracing::debug!("Got empty message");
                        }
                        Some(event) => {
                            yield Ok(RoundStreamEvent::from(event));
                        }
                    },
                    Ok(None) => {
                        yield Err(Error::EvenStreamEnded);
                    }
                    Err(er) => {
                        yield Err(Error::EventStreamError(er));
                    }
                }
            }
        };

        Ok(stream.boxed())
    }

    pub async fn get_round(&self, round_txid: String) -> Result<Option<Round>, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let response = inner
            .get_round(GetRoundRequest { txid: round_txid })
            .await
            .unwrap();

        let response = response.into_inner();
        Ok(response.round.map(Round::from))
    }

    pub fn inner(&self) -> Result<ArkServiceClient<Channel>, Error> {
        let inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        Ok(inner)
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

impl From<crate::generated::ark::v1::RoundFinalizationEvent> for RoundFinalizationEvent {
    fn from(value: crate::generated::ark::v1::RoundFinalizationEvent) -> Self {
        RoundFinalizationEvent {
            id: value.id,
            round_tx: value.round_tx,
            vtxo_tree: value.vtxo_tree.map(|tree| tree.into()),
            connectors: value.connectors,
            min_relay_fee_rate: value.min_relay_fee_rate,
        }
    }
}

impl From<crate::generated::ark::v1::RoundFinalizedEvent> for RoundFinalizedEvent {
    fn from(value: crate::generated::ark::v1::RoundFinalizedEvent) -> Self {
        RoundFinalizedEvent {
            id: value.id,
            round_txid: value.round_txid,
        }
    }
}

impl From<crate::generated::ark::v1::RoundFailed> for RoundFailedEvent {
    fn from(value: crate::generated::ark::v1::RoundFailed) -> Self {
        RoundFailedEvent {
            id: value.id,
            reason: value.reason,
        }
    }
}

impl From<crate::generated::ark::v1::RoundSigningEvent> for RoundSigningEvent {
    fn from(value: crate::generated::ark::v1::RoundSigningEvent) -> Self {
        RoundSigningEvent {
            id: value.id,
            cosigners_pubkeys: value.cosigners_pubkeys,
            unsigned_vtxo_tree: value.unsigned_vtxo_tree.map(|tree| tree.into()),
            unsigned_round_tx: value.unsigned_round_tx,
        }
    }
}

impl From<crate::generated::ark::v1::RoundSigningNoncesGeneratedEvent>
    for RoundSigningNoncesGeneratedEvent
{
    fn from(value: crate::generated::ark::v1::RoundSigningNoncesGeneratedEvent) -> Self {
        RoundSigningNoncesGeneratedEvent {
            id: value.id,
            tree_nonces: value.tree_nonces,
        }
    }
}

impl From<crate::generated::ark::v1::get_event_stream_response::Event> for RoundStreamEvent {
    fn from(value: crate::generated::ark::v1::get_event_stream_response::Event) -> Self {
        match value {
            crate::generated::ark::v1::get_event_stream_response::Event::RoundFinalization(e) => {
                RoundStreamEvent::RoundFinalization(e.into())
            }
            crate::generated::ark::v1::get_event_stream_response::Event::RoundFinalized(e) => {
                RoundStreamEvent::RoundFinalized(e.into())
            }
            crate::generated::ark::v1::get_event_stream_response::Event::RoundFailed(e) => {
                RoundStreamEvent::RoundFailed(e.into())
            }
            crate::generated::ark::v1::get_event_stream_response::Event::RoundSigning(e) => {
                RoundStreamEvent::RoundSigning(e.into())
            }
            crate::generated::ark::v1::get_event_stream_response::Event::RoundSigningNoncesGenerated(e) => {
                RoundStreamEvent::RoundSigningNoncesGenerated(e.into())
            }
        }
    }
}

impl From<crate::generated::ark::v1::Round> for Round {
    fn from(value: crate::generated::ark::v1::Round) -> Self {
        Round {
            id: value.id,
            start: value.start,
            end: value.end,
            round_tx: value.round_tx,
            vtxo_tree: value.vtxo_tree.map(|tree| tree.into()),
            forfeit_txs: value.forfeit_txs,
            connectors: value.connectors,
            stage: value.stage,
        }
    }
}
