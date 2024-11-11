use crate::ark_address::ArkAddress;
use crate::generated::ark::v1::get_event_stream_response;
use crate::generated::ark::v1::GetEventStreamRequest;
use crate::generated::ark::v1::Input;
use crate::generated::ark::v1::Outpoint;
use crate::generated::ark::v1::Output;
use crate::generated::ark::v1::PingRequest;
use crate::generated::ark::v1::RegisterInputsForNextRoundRequest;
use crate::generated::ark::v1::RegisterOutputsForNextRoundRequest;
use crate::generated::ark::v1::SubmitTreeNoncesRequest;
use crate::generated::ark::v1::SubmitTreeSignaturesRequest;
use crate::generated::ark::v1::Tree;
use crate::musig::to_zkp_pk;
use base64::Engine;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::hex::FromHex;
use bitcoin::key::Keypair;
use bitcoin::key::PublicKey;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::Transaction;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use error::Error;
use futures::FutureExt;
use miniscript::translate_hash_fail;
use miniscript::Descriptor;
use miniscript::ToPublicKey;
use miniscript::TranslatePk;
use miniscript::Translator;
use rand::CryptoRng;
use rand::Rng;
use std::collections::HashMap;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tonic::codegen::tokio_stream::StreamExt;
use zkp::new_musig_nonce_pair;
use zkp::Message;
use zkp::MusigAggNonce;
use zkp::MusigKeyAggCache;
use zkp::MusigPartialSignature;
use zkp::MusigPubNonce;
use zkp::MusigSecNonce;
use zkp::MusigSession;
use zkp::MusigSessionId;

pub mod generated {
    #[path = ""]
    pub mod ark {
        #[path = "ark.v1.rs"]
        pub mod v1;
    }
}

// TODO: Reconsider whether these should be public or not.
pub mod ark_address;
pub mod asp;
pub mod error;
pub mod musig;
pub mod script;

// TODO: Figure out how to integrate on-chain wallet. Probably use a trait and implement using
// `bdk`.

/// The Miniscript descriptor used for the boarding script.
///
/// We expect the ASP to provide this, but at the moment the ASP does not quite speak Miniscript.
///
/// We use `USER_0` and `USER_1` for the same user key, because `rust-miniscript` does not allow
/// repeating identifiers.
/// TODO: fixme: 9d0440=4195485 has been used by ArkD, but doesn't seem to be correct, it should be
/// 003a09=604672
const BOARDING_DESCRIPTOR_TEMPLATE_MINISCRIPT: &str =
    "tr(UNSPENDABLE_KEY,{and_v(v:pk(ASP),pk(USER_1)),and_v(v:older(4195485),pk(USER_0))})";

/// The Miniscript descriptor used for the default VTXO.
///
/// We expect the ASP to provide this, but at the moment the ASP does not quite speak Miniscript.
///
/// We use `USER_0` and `USER_1` for the same user key, because `rust-miniscript` does not allow
/// repeating identifiers.
const DEFAULT_VTXO_DESCRIPTOR_TEMPLATE_MINISCRIPT: &str =
    "tr(UNSPENDABLE_KEY,{and_v(v:pk(USER_1),pk(ASP)),and_v(v:older(TIMEOUT),pk(USER_0))})";

const UNSPENDABLE_KEY: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

const VTXO_INPUT_INDEX: usize = 0;

pub struct Client<B> {
    inner: asp::Client,
    pub name: String,
    pub kp: Keypair,
    pub asp_info: Option<asp::Info>,
    blockchain: Arc<B>,
}

#[derive(Clone, Debug)]
pub struct BoardingAddress {
    pub address: Address,
    pub descriptor: miniscript::descriptor::Tr<XOnlyPublicKey>,
    pub ark_descriptor: String,
}

#[derive(Debug, Clone)]
pub struct DefaultVtxoScript {
    pub asp: XOnlyPublicKey,
    pub owner: XOnlyPublicKey,
    pub exit_delay: u64,
    pub descriptor: miniscript::descriptor::Tr<XOnlyPublicKey>,
}

impl DefaultVtxoScript {
    pub fn new(asp: XOnlyPublicKey, owner: XOnlyPublicKey, exit_delay: u64) -> Result<Self, Error> {
        let vtxo_descriptor =
            DEFAULT_VTXO_DESCRIPTOR_TEMPLATE_MINISCRIPT.replace("TIMEOUT", &exit_delay.to_string());
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

        Ok(Self {
            asp,
            owner,
            exit_delay,
            descriptor: tr,
        })
    }
}

pub trait Blockchain {
    fn find_outpoint(
        &self,
        address: Address,
    ) -> impl std::future::Future<Output = Result<(OutPoint, Amount), Error>> + Send;
}

impl<B> Client<B>
where
    B: Blockchain,
{
    pub fn new(name: String, kp: Keypair, blockchain: Arc<B>) -> Self {
        let inner = asp::Client::new("http://localhost:7070".to_string());

        Self {
            inner,
            name,
            kp,
            asp_info: None,
            blockchain,
        }
    }

    pub async fn connect(&mut self) -> Result<(), Error> {
        self.inner.connect().await?;
        let info = self.inner.get_info().await?;

        self.asp_info = Some(info);

        Ok(())
    }

    // At the moment we are always generating the same address.
    pub fn get_offchain_address(&self) -> Result<ArkAddress, Error> {
        let asp_info = self.asp_info.clone().unwrap();

        let asp: PublicKey = asp_info.pubkey.parse().unwrap();
        let asp = asp.to_x_only_pubkey();
        let owner = self.kp.public_key().to_x_only_pubkey();

        let exit_delay = asp_info.unilateral_exit_delay as u64;

        let vtxo_script = DefaultVtxoScript::new(asp, owner, exit_delay).unwrap();

        let vtxo_tap_key = vtxo_script.descriptor.internal_key();

        let network = asp_info.network;

        let ark_address = ArkAddress::new(network, asp, *vtxo_tap_key);

        Ok(ark_address)
    }

    pub fn get_offchain_addresses(&self) -> Result<Vec<ArkAddress>, Error> {
        let address = self.get_offchain_address().unwrap();

        Ok(vec![address])
    }

    pub fn get_boarding_address(&self) -> Result<BoardingAddress, Error> {
        let asp_info = self.asp_info.clone().unwrap();

        let network = asp_info.network;

        let boarding_descriptor = asp_info.boarding_descriptor_template;

        let asp_pk: PublicKey = asp_info.pubkey.parse().unwrap();
        let asp_pk = asp_pk.to_x_only_pubkey();

        let our_pk = self.kp.public_key().to_x_only_pubkey();

        let unspendable_key: PublicKey = UNSPENDABLE_KEY.parse().unwrap();
        let unspendable_key = unspendable_key.to_x_only_pubkey();

        let mut pk_map = HashMap::new();

        pk_map.insert("UNSPENDABLE_KEY".to_string(), unspendable_key);
        pk_map.insert("USER_0".to_string(), our_pk);
        pk_map.insert("USER_1".to_string(), our_pk);
        pk_map.insert("ASP".to_string(), asp_pk);

        let mut t = StrPkTranslator { pk_map };

        let real_desc = boarding_descriptor.translate_pk(&mut t).unwrap();

        let address = real_desc.address(network).unwrap();

        let tr = match real_desc.clone() {
            Descriptor::Tr(tr) => tr,
            _ => unreachable!("Descriptor must be taproot"),
        };

        let ark_descriptor = asp_info
            .orig_boarding_descriptor
            .replace("USER", our_pk.to_string().as_str());
        Ok(BoardingAddress {
            address,
            descriptor: tr,
            ark_descriptor,
        })
    }

    pub fn get_boarding_addresses(&self) -> Result<Vec<BoardingAddress>, Error> {
        let address = self.get_boarding_address()?;
        Ok(vec![address])
    }

    pub async fn offchain_balance(&self) -> Result<Amount, Error> {
        let addresses: Vec<ArkAddress> = self.get_offchain_addresses()?;

        let mut total = Amount::ZERO;
        for address in addresses.into_iter() {
            let res = self.inner.list_vtxos(address).await?;

            let sum = res
                .spendable
                .iter()
                .fold(Amount::ZERO, |acc, x| acc + x.amount);

            total += sum;
        }

        Ok(total)
    }

    pub async fn board<R>(
        &self,
        secp: &Secp256k1<All>,
        secp_zkp: &zkp::Secp256k1<zkp::All>,
        rng: &mut R,
    ) -> Result<(), Error>
    where
        R: Rng + CryptoRng,
    {
        // Get all known boarding addresses.
        let boarding_addresses = self.get_boarding_addresses()?;

        let mut boarding_outputs: Vec<(OutPoint, BoardingAddress)> = Vec::new();
        let mut total_amount = Amount::ZERO;

        // Find outpoints for each boarding address.
        for boarding_address in boarding_addresses {
            let (outpoint, amount) = self
                .blockchain
                .find_outpoint(boarding_address.address.clone())
                .await?;

            // TODO: Filter out expired outpoints.
            boarding_outputs.push((outpoint, boarding_address));
            total_amount += amount;
        }

        // TODO: Include settlement of VTXOs.

        // Get off-chain address and send all funds to this address, no change output 🦄
        let address = self.get_offchain_address()?;

        tracing::info!(offchain_adress = ?address.encode(), ?boarding_outputs, "Attempting to board the ark");

        // Joining a round is likely to fail depending on the timing, so we keep retrying.
        //
        // TODO: Consider not retrying on all errors.
        let txid = loop {
            match self
                .join_next_ark_round(
                    secp,
                    secp_zkp,
                    rng,
                    boarding_outputs.clone(),
                    address,
                    total_amount,
                )
                .await
            {
                Ok(txid) => {
                    break txid;
                }
                Err(e) => {
                    tracing::error!("Failed to join the round: {e:?}. Retrying");
                }
            }
        };
        tracing::info!(txid, "Boarding success");

        Ok(())
    }

    async fn join_next_ark_round<R>(
        &self,
        secp: &Secp256k1<All>,
        secp_zkp: &zkp::Secp256k1<zkp::All>,
        rng: &mut R,
        outpoints: Vec<(OutPoint, BoardingAddress)>,
        address: ArkAddress,
        total_amount: Amount,
    ) -> Result<String, Error>
    // TODO: type the return type to TXID
    where
        R: Rng + CryptoRng,
    {
        // Generate an ephemeral key.
        let ephemeral_kp = Keypair::new(secp, rng);
        let inputs = outpoints
            .into_iter()
            .map(|(o, d)| Input {
                outpoint: Some(Outpoint {
                    txid: o.txid.to_string(),
                    vout: o.vout,
                }),
                descriptor: d.ark_descriptor,
            })
            .collect();

        // TODO: Move this into our API layer.
        let mut client = self.inner.inner.clone().ok_or(Error::Unknown)?;
        let response = client
            .register_inputs_for_next_round(RegisterInputsForNextRoundRequest {
                inputs,
                ephemeral_pubkey: Some(ephemeral_kp.public_key().to_string()),
            })
            .await
            .map_err(|_| Error::Unknown)?
            .into_inner();

        let register_inputs_for_next_round_id = response.id;

        tracing::debug!(
            id = register_inputs_for_next_round_id,
            "Registered for round"
        );

        client
            .register_outputs_for_next_round(RegisterOutputsForNextRoundRequest {
                id: register_inputs_for_next_round_id.clone(),
                outputs: vec![Output {
                    address: address.encode()?,
                    amount: total_amount.to_sat(),
                }],
            })
            .await
            .map_err(|_| Error::Unknown)?;

        // The protocol expects us to ping the ASP every 5 seconds to let the server know that we
        // are still interested in joining the round.
        let (ping_task, _ping_handle) = {
            let mut client = client.clone();
            let round_id = register_inputs_for_next_round_id.clone();
            async move {
                loop {
                    let response = client
                        .ping(PingRequest {
                            payment_id: round_id.clone(),
                        })
                        .await
                        .unwrap();
                    tracing::trace!(?response, "Sent ping");

                    tokio::time::sleep(Duration::from_millis(5000)).await
                }
            }
        }
        .remote_handle();

        tokio::spawn(ping_task);

        let mut client = client.clone();

        let response = client
            .get_event_stream(GetEventStreamRequest {})
            .await
            .map_err(|_| Error::Unknown)?;
        let mut stream = response.into_inner();

        let mut step = RoundStep::Start;
        let registered_round_id = register_inputs_for_next_round_id;

        let mut unsigned_round_tx: Option<Psbt> = None;
        let mut vtxo_tree: Option<Tree> = None;
        let mut cosigner_pks: Option<Vec<zkp::PublicKey>> = None;

        #[allow(clippy::type_complexity)]
        let mut our_nonce_tree: Option<Vec<Vec<Option<(MusigSecNonce, MusigPubNonce)>>>> = None;
        loop {
            match stream.next().await {
                Some(Ok(res)) => {
                    match res.event {
                        None => {
                            tracing::debug!("Got empty message");
                        }
                        Some(get_event_stream_response::Event::RoundSigning(e)) => {
                            if step != RoundStep::Start {
                                continue;
                            }
                            tracing::info!(round_id = e.id, "Round signing started");

                            let unsigned_vtxo_tree = e
                                .unsigned_vtxo_tree
                                .expect("we think this should always be some");

                            let secp_zkp = zkp::Secp256k1::new();

                            let mut nonce_tree: Vec<Vec<Option<(MusigSecNonce, MusigPubNonce)>>> =
                                Vec::new();
                            for level in unsigned_vtxo_tree.levels.iter() {
                                let mut nonces_level = vec![];
                                for _ in level.nodes.iter() {
                                    // TODO: Not sure if we want to generate a new session ID per
                                    // node in the VTXO tree.
                                    let alice_session_id = MusigSessionId::new(rng);
                                    let extra_rand = rng.gen();
                                    let (nonce_sk, nonce_pk) = new_musig_nonce_pair(
                                        &secp_zkp,
                                        alice_session_id,
                                        None,
                                        // Some(to_zkp_kp(&secp_zkp, &alice_kp).secret_key()),
                                        None,
                                        to_zkp_pk(ephemeral_kp.public_key()),
                                        None,
                                        Some(extra_rand),
                                    )
                                    .unwrap();

                                    nonces_level.push(Some((nonce_sk, nonce_pk)));
                                }
                                nonce_tree.push(nonces_level);
                            }

                            let pub_nonce_tree = nonce_tree
                                .iter()
                                .map(|level| {
                                    level
                                        .iter()
                                        .map(|kp| kp.as_ref().unwrap().1)
                                        .collect::<Vec<MusigPubNonce>>()
                                })
                                .collect();

                            our_nonce_tree = Some(nonce_tree);

                            let nonce_tree = encode_tree(pub_nonce_tree).unwrap();

                            client
                                .submit_tree_nonces(SubmitTreeNoncesRequest {
                                    round_id: e.id,
                                    pubkey: ephemeral_kp.public_key().to_string(),
                                    tree_nonces: nonce_tree.to_lower_hex_string(),
                                })
                                .await
                                .unwrap();

                            vtxo_tree = Some(unsigned_vtxo_tree);

                            let cosigner_public_keys = e
                                .cosigners_pubkeys
                                .into_iter()
                                .map(|pk| pk.parse().map_err(|_| Error::Unknown))
                                .collect::<Result<Vec<zkp::PublicKey>, Error>>()
                                .unwrap();

                            cosigner_pks = Some(cosigner_public_keys);

                            unsigned_round_tx = {
                                let psbt = base64::engine::GeneralPurpose::new(
                                    &base64::alphabet::STANDARD,
                                    base64::engine::GeneralPurposeConfig::new(),
                                )
                                .decode(&e.unsigned_round_tx)
                                .unwrap();

                                let psbt = Psbt::deserialize(&psbt).unwrap();

                                Some(psbt)
                            };

                            step = step.next();
                            continue;
                        }
                        Some(get_event_stream_response::Event::RoundSigningNoncesGenerated(e)) => {
                            if step != RoundStep::RoundSigningStarted {
                                continue;
                            }

                            let nonce_tree = decode_nonce_tree(e.tree_nonces).unwrap();

                            tracing::debug!(
                                round_id = e.id,
                                ?nonce_tree,
                                "Round combined nonces generated"
                            );

                            let vtxo_tree = vtxo_tree.clone().expect("To have received it");
                            let cosigner_pks = cosigner_pks.clone().expect("To have received them");
                            let mut our_nonce_tree =
                                our_nonce_tree.take().expect("To have generated them");

                            let key_agg_cache =
                                MusigKeyAggCache::new(secp_zkp, cosigner_pks.as_slice());

                            let ephemeral_kp = zkp::Keypair::from_seckey_slice(
                                secp_zkp,
                                &ephemeral_kp.secret_bytes(),
                            )
                            .unwrap();

                            let mut sig_tree: Vec<Vec<MusigPartialSignature>> = Vec::new();
                            for (i, level) in vtxo_tree.levels.iter().enumerate() {
                                let mut sigs_level = Vec::new();
                                for (j, node) in level.nodes.iter().enumerate() {
                                    tracing::debug!(i, j, ?node, "Generating partial signature");

                                    let nonces = nonce_tree[i][j];
                                    let agg_nonce = MusigAggNonce::new(secp_zkp, &[nonces]);

                                    let psbt = base64::engine::GeneralPurpose::new(
                                        &base64::alphabet::STANDARD,
                                        base64::engine::GeneralPurposeConfig::new(),
                                    )
                                    .decode(&node.tx)
                                    .unwrap();

                                    let psbt = Psbt::deserialize(&psbt).unwrap();
                                    let tx = psbt.unsigned_tx;

                                    // We expect a single input to a VTXO.
                                    let parent_txid: Txid = node.parent_txid.parse().unwrap();

                                    let input_vout =
                                        tx.input[VTXO_INPUT_INDEX].previous_output.vout as usize;

                                    let prevout = if i == 0 {
                                        unsigned_round_tx.clone().unwrap().unsigned_tx.output
                                            [input_vout]
                                            .clone()
                                    } else {
                                        let parent_level = &vtxo_tree.levels[i - 1];
                                        let parent_tx: Transaction = parent_level
                                            .nodes
                                            .iter()
                                            .find_map(|node| {
                                                let txid: Txid = node.txid.parse().unwrap();
                                                (txid == parent_txid).then_some({
                                                    let tx = Vec::from_hex(&node.tx).unwrap();
                                                    deserialize(&tx).unwrap()
                                                })
                                            })
                                            .unwrap();

                                        parent_tx.output[input_vout].clone()
                                    };

                                    let prevouts = [prevout];
                                    let prevouts = Prevouts::All(&prevouts);

                                    let tap_sighash = SighashCache::new(tx)
                                        .taproot_key_spend_signature_hash(
                                            VTXO_INPUT_INDEX,
                                            &prevouts,
                                            bitcoin::TapSighashType::Default,
                                        )
                                        .unwrap();

                                    let msg = Message::from_digest(
                                        tap_sighash.to_raw_hash().to_byte_array(),
                                    );

                                    let nonce_sk = our_nonce_tree[i][j].take().unwrap().0;

                                    let sig =
                                        MusigSession::new(secp_zkp, &key_agg_cache, agg_nonce, msg)
                                            .partial_sign(
                                                secp_zkp,
                                                nonce_sk,
                                                &ephemeral_kp,
                                                &key_agg_cache,
                                            )
                                            .unwrap();

                                    sigs_level.push(sig);
                                }
                                sig_tree.push(sigs_level);
                            }

                            let sig_tree = encode_tree(sig_tree).unwrap();

                            client
                                .submit_tree_signatures(SubmitTreeSignaturesRequest {
                                    round_id: e.id,
                                    pubkey: ephemeral_kp.public_key().to_string(),
                                    tree_signatures: sig_tree.to_lower_hex_string(),
                                })
                                .await
                                .unwrap();

                            step = step.next();
                        }
                        Some(get_event_stream_response::Event::RoundFinalization(e)) => {
                            if step != RoundStep::RoundFinalization {
                                continue;
                            }
                            tracing::debug!(?e, "Round finalization started");

                            step = step.next();
                            // TODO: implement me
                        }
                        Some(get_event_stream_response::Event::RoundFinalized(e)) => {
                            tracing::info!(round_id = e.id, txid = e.round_txid, "Round finalized");
                            return Ok(e.round_txid);
                        }
                        Some(get_event_stream_response::Event::RoundFailed(e)) => {
                            if e.id == registered_round_id {
                                tracing::error!(
                                    round_id = e.id,
                                    reason = e.reason,
                                    "Failed registering in round"
                                );
                                // TODO: return a different error
                                return Err(Error::Unknown);
                            }
                            tracing::debug!("Got message: {e:?}");
                            continue;
                        }
                    }
                }
                Some(Err(e)) => {
                    tracing::error!("Got error from round event stream: {e:?}");
                    return Err(Error::Unknown);
                }
                None => {
                    tracing::error!("Dropped to round event stream");
                    return Err(Error::Unknown);
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RoundStep {
    Start,
    RoundSigningStarted,
    RoundSigningNoncesGenerated,
    RoundFinalization,
    Finalized,
}

impl RoundStep {
    fn next(&self) -> RoundStep {
        match self {
            RoundStep::Start => RoundStep::RoundSigningStarted,
            RoundStep::RoundSigningStarted => RoundStep::RoundSigningNoncesGenerated,
            RoundStep::RoundSigningNoncesGenerated => RoundStep::RoundFinalization,
            RoundStep::RoundFinalization => RoundStep::Finalized,
            RoundStep::Finalized => RoundStep::Finalized, // we can't go further
        }
    }
}

struct StrPkTranslator {
    pk_map: HashMap<String, XOnlyPublicKey>,
}

impl Translator<String, XOnlyPublicKey, ()> for StrPkTranslator {
    fn pk(&mut self, pk: &String) -> Result<XOnlyPublicKey, ()> {
        self.pk_map.get(pk).copied().ok_or(())
    }

    // We don't need to implement these methods as we are not using them in the policy.
    // Fail if we encounter any hash fragments. See also translate_hash_clone! macro.
    translate_hash_fail!(String, XOnlyPublicKey, ());
}

const COLUMN_SEPARATOR: u8 = b'|';
const ROW_SEPARATOR: u8 = b'/';

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

impl ToBytes for MusigPubNonce {
    fn to_bytes(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
}

impl ToBytes for MusigPartialSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
}

pub fn encode_tree<T>(tree: Vec<Vec<T>>) -> io::Result<Vec<u8>>
where
    T: ToBytes,
{
    let mut buf = Vec::new();

    // [[key0], [key1, key2], [key3, key4, key5, key6]]
    for level in tree {
        for pk in level {
            buf.write_all(&[COLUMN_SEPARATOR])?;

            buf.write_all(&pk.to_bytes())?;
        }

        buf.write_all(&[ROW_SEPARATOR])?;
    }

    Ok(buf)
}

pub fn decode_nonce_tree(serialized: String) -> io::Result<Vec<Vec<MusigPubNonce>>> {
    let mut matrix: Vec<Vec<MusigPubNonce>> = Vec::new();
    let mut row = Vec::new();

    let bytes = Vec::from_hex(&serialized).unwrap();

    let mut reader = Cursor::new(&bytes);

    // |key0/|key1|key2/|key3|key4|key5|key6/
    loop {
        let mut separator = [0u8; 1];

        match reader.read(&mut separator) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let b = separator[0];

                if b == ROW_SEPARATOR {
                    if !row.is_empty() {
                        matrix.push(row);
                        row = Vec::new();
                    }
                    continue;
                }

                let mut pk_buffer = [0u8; 66];
                reader.read_exact(&mut pk_buffer).unwrap();
                let pk = MusigPubNonce::from_slice(&pk_buffer).unwrap();

                row.push(pk);
            }
            Err(e) => return Err(e),
        }
    }

    if !row.is_empty() {
        matrix.push(row);
    }

    Ok(matrix)
}

#[cfg(test)]
pub mod tests {
    use crate::decode_nonce_tree;
    use crate::encode_tree;
    use crate::error::Error;
    use crate::Blockchain;
    use crate::Client;
    use bitcoin::hex::DisplayHex;
    use bitcoin::hex::FromHex;
    use bitcoin::key::Keypair;
    use bitcoin::key::Secp256k1;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::Address;
    use bitcoin::Amount;
    use bitcoin::OutPoint;
    use bitcoin::Transaction;
    use bitcoin::Txid;
    use rand::thread_rng;
    use regex::Regex;
    use std::collections::HashMap;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::Once;
    use std::time::Duration;
    use zkp::MusigPubNonce;
    use zkp::MusigSecNonce;

    struct Nigiri {
        utxos: Mutex<HashMap<bitcoin::Address, (OutPoint, Amount)>>,
    }

    impl Nigiri {
        pub fn new() -> Self {
            Self {
                utxos: Mutex::new(HashMap::new()),
            }
        }

        async fn faucet_fund(&self, address: Address, amount: Amount) -> OutPoint {
            let res = Command::new("nigiri")
                .args(["faucet", &address.to_string(), &amount.to_btc().to_string()])
                .output()
                .unwrap();

            assert!(res.status.success());

            let text = String::from_utf8(res.stdout).unwrap();
            let re = Regex::new(r"txId: ([0-9a-fA-F]{64})").unwrap();

            let txid = match re.captures(&text) {
                Some(captures) => match captures.get(1) {
                    Some(txid) => txid.as_str(),
                    _ => panic!("Could not parse TXID"),
                },
                None => {
                    panic!("Could not parse TXID");
                }
            };

            let txid: Txid = txid.parse().unwrap();

            let res = Command::new("nigiri")
                .args(["rpc", "getrawtransaction", &txid.to_string()])
                .output()
                .unwrap();

            let tx = String::from_utf8(res.stdout).unwrap();

            let tx = Vec::from_hex(tx.trim()).unwrap();
            let tx: Transaction = bitcoin::consensus::deserialize(&tx).unwrap();

            let (vout, _) = tx
                .output
                .iter()
                .enumerate()
                .find(|(_, o)| o.script_pubkey == address.script_pubkey())
                .unwrap();

            let point = OutPoint {
                txid,
                vout: vout as u32,
            };
            let mut guard = self.utxos.lock().unwrap();
            guard.insert(address, (point, amount));

            point
        }
    }

    impl Blockchain for Nigiri {
        async fn find_outpoint(
            &self,
            address: bitcoin::Address,
        ) -> Result<(OutPoint, Amount), Error> {
            let guard = self.utxos.lock().unwrap();
            let value = guard.get(&address).ok_or(Error::Unknown)?;
            Ok(*value)
        }
    }

    async fn setup_client(name: String, kp: Keypair, nigiri: Arc<Nigiri>) -> Client<Nigiri> {
        let mut client = Client::new(name, kp, nigiri);

        client.connect().await.unwrap();

        client
    }

    #[test]
    fn nonce_tree_round_trip() {
        let a_bytes = Vec::from_hex("03a2ca7605303774152c9af458c9abdfa5636a8028e7bb91d4e2e6b69b60a7961e02e7d8f8d98e1b8452bec2b8132a49b97b8d3a5e8a71ce6d1b1b5a58d9263ac8dd").unwrap();
        let b_bytes = Vec::from_hex("021a9d01ba9ef321b512f1368ff426bb8e9a7edf4ae5f0e65691a08eef604acfc7026fc797f4f8a81af2f44aee6084a34227c16656eececa41d550fc1f0f6fe765fd").unwrap();
        let c_bytes = Vec::from_hex("034b7d66fdff36cf53d5fb86f0548f28d88247bf43292c8c76379c6c3f22a45ffe0298f6843979d3b38bbdc186d30fdf0fc70e1335aa727544af49804b592ada90e8").unwrap();

        let a = (
            MusigSecNonce::dangerous_from_bytes([1u8; 132]),
            MusigPubNonce::from_slice(&a_bytes).unwrap(),
        );
        let b = (
            MusigSecNonce::dangerous_from_bytes([2u8; 132]),
            MusigPubNonce::from_slice(&b_bytes).unwrap(),
        );
        let c = (
            MusigSecNonce::dangerous_from_bytes([3u8; 132]),
            MusigPubNonce::from_slice(&c_bytes).unwrap(),
        );

        let nonce_tree = vec![vec![a.1], vec![b.1, c.1]];

        let serialized = encode_tree(nonce_tree).unwrap().to_lower_hex_string();

        let deserialized = decode_nonce_tree(serialized).unwrap();

        let pub_nonce_tree = vec![
            vec![MusigPubNonce::from_slice(&a_bytes).unwrap()],
            vec![
                MusigPubNonce::from_slice(&b_bytes).unwrap(),
                MusigPubNonce::from_slice(&c_bytes).unwrap(),
            ],
        ];

        assert_eq!(pub_nonce_tree, deserialized);
    }

    #[tokio::test]
    pub async fn e2e() {
        init_tracing();
        let nigiri = Arc::new(Nigiri::new());

        let secp = Secp256k1::new();
        let secp_zkp = zkp::Secp256k1::new();
        let mut rng = thread_rng();

        let key = SecretKey::new(&mut rng);
        let keypair = Keypair::from_secret_key(&secp, &key);

        let alice = setup_client("alice".to_string(), keypair, nigiri.clone()).await;

        let alice_boarding_address = alice.get_boarding_address().unwrap();

        let boarding_output = nigiri
            .faucet_fund(alice_boarding_address.address, Amount::ONE_BTC)
            .await;

        tracing::debug!("Boarding output: {boarding_output:?}");

        let offchain_balance = alice.offchain_balance().await.unwrap();

        tracing::debug!("Alice offchain balance: {offchain_balance}");

        alice.board(&secp, &secp_zkp, &mut rng).await.unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
    }

    pub fn init_tracing() {
        static TRACING_TEST_SUBSCRIBER: Once = Once::new();

        TRACING_TEST_SUBSCRIBER.call_once(|| {
            tracing_subscriber::fmt()
                .with_env_filter(
                    "debug,\
                 bdk=info,\
                 tower=info,\
                 hyper_util=info,\
                 h2=warn",
                )
                .with_test_writer()
                .init()
        })
    }
}
