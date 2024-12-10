use crate::ark_address::ArkAddress;
use crate::asp::tree;
use crate::asp::types::Info;
use crate::asp::types::ListVtxo;
use crate::asp::types::VtxoOutPoint;
use crate::asp::Error;
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

#[derive(Debug)]
pub struct RoundInputs {
    pub outpoint: Option<OutPoint>,
    pub descriptor: String,
}

pub struct RoundOutputs {
    // TODO: Would be cool to have a type here which accepts `ArkAddress` and `bitcoin::Address`.
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
    pub txid: Txid,
    pub tx: Psbt,
    pub parent_txid: Txid,
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
        let client = ArkServiceClient::connect(self.url.clone())
            .await
            .map_err(Error::connect)?;

        self.inner = Some(client);
        Ok(())
    }

    pub async fn get_info(&mut self) -> Result<Info, Error> {
        let mut client = self.inner_client()?;

        let response = client
            .get_info(GetInfoRequest {})
            .await
            .map_err(Error::request)?;

        response.into_inner().try_into()
    }

    pub async fn list_vtxos(&self, address: ArkAddress) -> Result<ListVtxo, Error> {
        let address = address.encode();

        let mut client = self.inner_client()?;

        let response = client
            .list_vtxos(ListVtxosRequest { address })
            .await
            .map_err(Error::request)?;

        let spent = response
            .get_ref()
            .spendable_vtxos
            .iter()
            .map(VtxoOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let spendable = response
            .get_ref()
            .spendable_vtxos
            .iter()
            .map(VtxoOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ListVtxo { spent, spendable })
    }

    pub async fn register_inputs_for_next_round(
        &self,
        ephemeral_key: PublicKey,
        inputs: Vec<RoundInputs>,
    ) -> Result<String, Error> {
        let mut client = self.inner_client()?;

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

        let response = client
            .register_inputs_for_next_round(RegisterInputsForNextRoundRequest {
                inputs,
                ephemeral_pubkey: Some(ephemeral_key.to_string()),
                notes: Vec::new(),
            })
            .await
            .map_err(Error::request)?;
        let payment_id = response.into_inner().id;

        Ok(payment_id)
    }

    pub async fn register_outputs_for_next_round(
        &self,
        payment_id: String,
        outpouts: Vec<RoundOutputs>,
    ) -> Result<(), Error> {
        let mut client = self.inner_client()?;

        let outputs = outpouts
            .iter()
            .map(|out| Output {
                address: out.address.clone(),
                amount: out.amount.to_sat(),
            })
            .collect();

        client
            .register_outputs_for_next_round(RegisterOutputsForNextRoundRequest {
                id: payment_id,
                outputs,
            })
            .await
            .map_err(Error::request)?;

        Ok(())
    }

    pub async fn send_payment(
        &self,
        inputs: Vec<PaymentInput>,
        outputs: Vec<PaymentOutput>,
    ) -> Result<Psbt, Error> {
        let mut client = self.inner_client()?;

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
                address: output.address.encode(),
                amount: output.amount.to_sat(),
            })
            .collect();

        let res = client
            .create_payment(CreatePaymentRequest { inputs, outputs })
            .await
            .map_err(Error::request)?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let signed_redeem_psbt = {
            let psbt = base64
                .decode(&res.into_inner().signed_redeem_tx)
                .map_err(Error::conversion)?;

            Psbt::deserialize(&psbt).map_err(Error::conversion)?
        };

        Ok(signed_redeem_psbt)
    }

    pub async fn complete_payment_request(&self, signed_psbt: Psbt) -> Result<Txid, Error> {
        let mut client = self.inner_client()?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let signed_psbt_base64 = base64.encode(signed_psbt.serialize());

        let _response = client
            .complete_payment(CompletePaymentRequest {
                signed_redeem_tx: signed_psbt_base64,
            })
            .await
            .map_err(Error::request)?;
        let txid = signed_psbt.unsigned_tx.compute_txid();

        Ok(txid)
    }

    pub async fn ping(&self, payment_id: String) -> Result<(), Error> {
        let mut client = self.inner_client()?;

        client
            .ping(PingRequest { payment_id })
            .await
            .map_err(|e| Error::ping(e.message().to_string()))?;

        Ok(())
    }

    pub async fn submit_tree_nonces(
        &self,
        round_id: String,
        ephemeral_pubkey: PublicKey,
        pub_nonce_tree: Vec<Vec<zkp::MusigPubNonce>>,
    ) -> Result<(), Error> {
        let mut client = self.inner_client()?;

        let nonce_tree = tree::encode_tree(pub_nonce_tree).map_err(Error::conversion)?;

        client
            .submit_tree_nonces(SubmitTreeNoncesRequest {
                round_id,
                pubkey: ephemeral_pubkey.to_string(),
                tree_nonces: nonce_tree.to_lower_hex_string(),
            })
            .await
            .map_err(Error::request)?;

        Ok(())
    }

    pub async fn submit_tree_signatures(
        &self,
        round_id: String,
        ephemeral_pubkey: zkp::PublicKey,
        partial_sig_tree: Vec<Vec<zkp::MusigPartialSignature>>,
    ) -> Result<(), Error> {
        let mut client = self.inner_client()?;

        let tree_signatures = tree::encode_tree(partial_sig_tree).map_err(Error::conversion)?;

        client
            .submit_tree_signatures(SubmitTreeSignaturesRequest {
                round_id,
                pubkey: ephemeral_pubkey.to_string(),
                tree_signatures: tree_signatures.to_lower_hex_string(),
            })
            .await
            .map_err(Error::request)?;

        Ok(())
    }

    pub async fn submit_signed_forfeit_txs(
        &self,
        signed_forfeit_txs: Vec<Psbt>,
        signed_round_psbt: Psbt,
    ) -> Result<(), Error> {
        let mut client = self.inner_client()?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        client
            .submit_signed_forfeit_txs(SubmitSignedForfeitTxsRequest {
                signed_forfeit_txs: signed_forfeit_txs
                    .iter()
                    .map(|psbt| base64.encode(psbt.serialize()))
                    .collect(),
                signed_round_tx: Some(base64.encode(signed_round_psbt.serialize())),
            })
            .await
            .map_err(Error::request)?;

        Ok(())
    }

    pub async fn get_event_stream(
        &self,
    ) -> Result<impl Stream<Item = Result<RoundStreamEvent, Error>> + Unpin, Error> {
        let mut client = self.inner_client()?;

        let response = client
            .get_event_stream(GetEventStreamRequest {})
            .await
            .map_err(Error::request)?;
        let mut stream = response.into_inner();

        let stream = stream! {
            loop {
                match stream.try_next().await {
                    Ok(Some(event)) => match event.event {
                        None => {
                            tracing::debug!("Got empty message");
                        }
                        Some(event) => {
                            yield Ok(RoundStreamEvent::try_from(event)?);
                        }
                    },
                    Ok(None) => {
                        yield Err(Error::event_stream_disconnect());
                    }
                    Err(e) => {
                        yield Err(Error::event_stream(e));
                    }
                }
            }
        };

        Ok(stream.boxed())
    }

    pub async fn get_round(&self, round_txid: String) -> Result<Option<Round>, Error> {
        let mut client = self.inner_client()?;

        let response = client
            .get_round(GetRoundRequest { txid: round_txid })
            .await
            .map_err(Error::request)?;

        let response = response.into_inner();
        let round = response.round.map(Round::try_from).transpose()?;

        Ok(round)
    }

    fn inner_client(&self) -> Result<ArkServiceClient<Channel>, Error> {
        // Cloning an `ArkServiceClient<Channel>` is cheap.
        self.inner.clone().ok_or(Error::not_connected())
    }
}

impl TryFrom<crate::generated::ark::v1::Tree> for Tree {
    type Error = Error;

    fn try_from(value: crate::generated::ark::v1::Tree) -> Result<Self, Self::Error> {
        let levels = value
            .levels
            .into_iter()
            .map(|level| level.try_into())
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Tree { levels })
    }
}

impl TryFrom<crate::generated::ark::v1::TreeLevel> for TreeLevel {
    type Error = Error;

    fn try_from(value: crate::generated::ark::v1::TreeLevel) -> Result<Self, Self::Error> {
        let nodes = value
            .nodes
            .into_iter()
            .map(|node| node.try_into())
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(TreeLevel { nodes })
    }
}

impl TryFrom<crate::generated::ark::v1::Node> for Node {
    type Error = Error;

    fn try_from(value: crate::generated::ark::v1::Node) -> Result<Self, Self::Error> {
        let txid: Txid = value.txid.parse().map_err(Error::conversion)?;

        let tx = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        )
        .decode(&value.tx)
        .map_err(Error::conversion)?;

        let tx = Psbt::deserialize(&tx).map_err(Error::conversion)?;

        let parent_txid: Txid = value.parent_txid.parse().map_err(Error::conversion)?;

        Ok(Node {
            txid,
            tx,
            parent_txid,
        })
    }
}

impl TryFrom<crate::generated::ark::v1::RoundFinalizationEvent> for RoundFinalizationEvent {
    type Error = Error;

    fn try_from(
        value: crate::generated::ark::v1::RoundFinalizationEvent,
    ) -> Result<Self, Self::Error> {
        let base64 = &base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let vtxo_tree = value.vtxo_tree.map(|tree| tree.try_into()).transpose()?;

        let round_tx = base64.decode(&value.round_tx).map_err(Error::conversion)?;

        let round_tx = Psbt::deserialize(&round_tx).map_err(Error::conversion)?;

        let connectors = value
            .connectors
            .into_iter()
            .map(|t| {
                let psbt = base64.decode(&t).map_err(Error::conversion)?;
                let psbt = Psbt::deserialize(&psbt).map_err(Error::conversion)?;
                Ok(psbt)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(RoundFinalizationEvent {
            id: value.id,
            round_tx,
            vtxo_tree,
            connectors,
            min_relay_fee_rate: value.min_relay_fee_rate,
        })
    }
}

impl TryFrom<crate::generated::ark::v1::RoundFinalizedEvent> for RoundFinalizedEvent {
    type Error = Error;

    fn try_from(
        value: crate::generated::ark::v1::RoundFinalizedEvent,
    ) -> Result<Self, Self::Error> {
        let round_txid = value.round_txid.parse().map_err(Error::conversion)?;

        Ok(RoundFinalizedEvent {
            id: value.id,
            round_txid,
        })
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

impl TryFrom<crate::generated::ark::v1::RoundSigningEvent> for RoundSigningEvent {
    type Error = Error;

    fn try_from(value: crate::generated::ark::v1::RoundSigningEvent) -> Result<Self, Self::Error> {
        let unsigned_round_tx = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        )
        .decode(&value.unsigned_round_tx)
        .map_err(Error::conversion)?;

        let unsigned_vtxo_tree = value
            .unsigned_vtxo_tree
            .map(|tree| tree.try_into())
            .transpose()?;

        let unsigned_round_tx = Psbt::deserialize(&unsigned_round_tx).map_err(Error::conversion)?;

        Ok(RoundSigningEvent {
            id: value.id,
            cosigners_pubkeys: value
                .cosigners_pubkeys
                .into_iter()
                .map(|pk| pk.parse().map_err(Error::conversion))
                .collect::<Result<Vec<_>, Error>>()?,
            unsigned_vtxo_tree,
            unsigned_round_tx,
        })
    }
}

impl TryFrom<crate::generated::ark::v1::RoundSigningNoncesGeneratedEvent>
    for RoundSigningNoncesGeneratedEvent
{
    type Error = Error;

    fn try_from(
        value: crate::generated::ark::v1::RoundSigningNoncesGeneratedEvent,
    ) -> Result<Self, Self::Error> {
        let tree_nonces = crate::asp::decode_tree(value.tree_nonces)?;

        Ok(RoundSigningNoncesGeneratedEvent {
            id: value.id,
            tree_nonces,
        })
    }
}

impl TryFrom<crate::generated::ark::v1::get_event_stream_response::Event> for RoundStreamEvent {
    type Error = Error;

    fn try_from(
        value: crate::generated::ark::v1::get_event_stream_response::Event,
    ) -> Result<Self, Self::Error> {
        Ok(match value {
            crate::generated::ark::v1::get_event_stream_response::Event::RoundFinalization(e) => {
                RoundStreamEvent::RoundFinalization(e.try_into()?)
            }
            crate::generated::ark::v1::get_event_stream_response::Event::RoundFinalized(e) => {
                RoundStreamEvent::RoundFinalized(e.try_into()?)
            }
            crate::generated::ark::v1::get_event_stream_response::Event::RoundFailed(e) => {
                RoundStreamEvent::RoundFailed(e.into())
            }
            crate::generated::ark::v1::get_event_stream_response::Event::RoundSigning(e) => {
                RoundStreamEvent::RoundSigning(e.try_into()?)
            }
            crate::generated::ark::v1::get_event_stream_response::Event::RoundSigningNoncesGenerated(e) => {
                RoundStreamEvent::RoundSigningNoncesGenerated(e.try_into()?)
            }
        })
    }
}

impl TryFrom<crate::generated::ark::v1::Round> for Round {
    type Error = Error;

    fn try_from(value: crate::generated::ark::v1::Round) -> Result<Self, Self::Error> {
        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let round_tx = {
            let psbt = base64.decode(&value.round_tx).map_err(Error::conversion)?;
            Psbt::deserialize(&psbt).map_err(Error::conversion)?
        };

        let vtxo_tree = value.vtxo_tree.map(|tree| tree.try_into()).transpose()?;

        let forfeit_txs = value
            .forfeit_txs
            .into_iter()
            .map(|t| {
                let psbt = base64.decode(&t).map_err(Error::conversion)?;
                let psbt = Psbt::deserialize(&psbt).map_err(Error::conversion)?;
                Ok(psbt)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let connectors = value
            .connectors
            .into_iter()
            .map(|t| {
                let psbt = base64.decode(&t).map_err(Error::conversion)?;
                let psbt = Psbt::deserialize(&psbt).map_err(Error::conversion)?;
                Ok(psbt)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Round {
            id: value.id,
            start: value.start,
            end: value.end,
            round_tx,
            vtxo_tree,
            forfeit_txs,
            connectors,
            stage: value.stage,
        })
    }
}
