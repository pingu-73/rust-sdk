use crate::ark_address::ArkAddress;
use crate::asp::ListVtxo;
use crate::asp::Vtxo;
use crate::boarding_address::BoardingAddress;
use crate::coinselect::coin_select;
use crate::conversions::from_zkp_xonly;
use crate::conversions::to_zkp_pk;
use crate::default_vtxo_script::DefaultVtxoScript;
use crate::generated::ark::v1::get_event_stream_response;
use crate::generated::ark::v1::AsyncPaymentInput;
use crate::generated::ark::v1::CompletePaymentRequest;
use crate::generated::ark::v1::CreatePaymentRequest;
use crate::generated::ark::v1::GetEventStreamRequest;
use crate::generated::ark::v1::GetRoundRequest;
use crate::generated::ark::v1::Input;
use crate::generated::ark::v1::Outpoint;
use crate::generated::ark::v1::Output;
use crate::generated::ark::v1::PingRequest;
use crate::generated::ark::v1::RegisterInputsForNextRoundRequest;
use crate::generated::ark::v1::RegisterOutputsForNextRoundRequest;
use crate::generated::ark::v1::SubmitSignedForfeitTxsRequest;
use crate::generated::ark::v1::SubmitTreeNoncesRequest;
use crate::generated::ark::v1::SubmitTreeSignaturesRequest;
use crate::generated::ark::v1::Tree;
use crate::script::extract_sequence_from_csv_sig_closure;
use crate::script::CsvSigClosure;
use base64::Engine;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::constants::WITNESS_SCALE_FACTOR;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::hex::FromHex;
use bitcoin::key::Keypair;
use bitcoin::key::PublicKey;
use bitcoin::key::Secp256k1;
use bitcoin::relative;
use bitcoin::secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction;
use bitcoin::Address;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::FeeRate;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::ScriptBuf;
use bitcoin::TapLeafHash;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::VarInt;
use bitcoin::Witness;
use error::Error;
use futures::FutureExt;
use miniscript::Descriptor;
use miniscript::ToPublicKey;
use miniscript::TranslatePk;
use rand::CryptoRng;
use rand::Rng;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tonic::codegen::tokio_stream::StreamExt;
use zkp::new_musig_nonce_pair;
use zkp::MusigAggNonce;
use zkp::MusigKeyAggCache;
use zkp::MusigPartialSignature;
use zkp::MusigPubNonce;
use zkp::MusigSecNonce;
use zkp::MusigSession;
use zkp::MusigSessionId;

#[allow(warnings)]
#[allow(clippy::all)]
mod generated {
    #[path = ""]
    pub mod ark {
        #[path = "ark.v1.rs"]
        pub mod v1;
    }
}

// TODO: Reconsider whether these should be public or not.
pub mod ark_address;
pub mod asp;
pub mod boarding_address;
pub mod default_vtxo_script;
pub mod error;
pub mod script;

mod coinselect;
mod conversions;

// TODO: Figure out how to integrate on-chain wallet. Probably use a trait and implement using
// `bdk`.

/// The Miniscript descriptor used for the boarding script.
///
/// We expect the ASP to provide this, but at the moment the ASP does not quite speak Miniscript.
///
/// We use `USER_0` and `USER_1` for the same user key, because `rust-miniscript` does not allow
/// repeating identifiers.
const BOARDING_DESCRIPTOR_TEMPLATE_MINISCRIPT: &str =
    "tr(UNSPENDABLE_KEY,{and_v(v:pk(ASP),pk(USER_1)),and_v(v:older(TIMEOUT),pk(USER_0))})";

const UNSPENDABLE_KEY: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

const VTXO_INPUT_INDEX: usize = 0;

pub struct Client<B> {
    inner: asp::Client,
    pub name: String,
    pub kp: Keypair,
    pub asp_info: Option<asp::Info>,
    blockchain: Arc<B>,
    secp: Secp256k1<All>,
    secp_zkp: zkp::Secp256k1<zkp::All>,
}

enum RoundOutputType {
    Board {
        to_address: ArkAddress,
        to_amount: Amount,
    },
    OffBoard {
        to_address: Address,
        to_amount: Amount,
        change_address: ArkAddress,
        change_amount: Amount,
    },
}

pub trait Blockchain {
    fn find_outpoint(
        &self,
        address: Address,
    ) -> impl std::future::Future<Output = Result<Option<(OutPoint, Amount)>, Error>> + Send;

    fn find_tx(
        &self,
        txid: &Txid,
    ) -> impl std::future::Future<Output = Result<Option<Transaction>, Error>> + Send;

    fn broadcast(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<(), Error>> + Send;
}

struct RedeemBranch {
    _vtxo: Vtxo,
    branch: Vec<Psbt>,
    _lifetime: Duration,
}

impl<B> Client<B>
where
    B: Blockchain,
{
    pub fn new(name: String, kp: Keypair, blockchain: Arc<B>) -> Self {
        let secp = Secp256k1::new();
        let secp_zkp = zkp::Secp256k1::new();

        let inner = asp::Client::new("http://localhost:7070".to_string());

        Self {
            inner,
            name,
            kp,
            asp_info: None,
            blockchain,
            secp,
            secp_zkp,
        }
    }

    pub async fn connect(&mut self) -> Result<(), Error> {
        self.inner.connect().await?;
        let info = self.inner.get_info().await?;

        self.asp_info = Some(info);

        Ok(())
    }

    // At the moment we are always generating the same address.
    pub fn get_offchain_address(&self) -> Result<(ArkAddress, DefaultVtxoScript), Error> {
        let asp_info = self.asp_info.clone().unwrap();

        let asp: PublicKey = asp_info.pubkey.parse().unwrap();
        let asp = asp.to_x_only_pubkey();
        let owner = self.kp.public_key().to_x_only_pubkey();

        let exit_delay = asp_info.unilateral_exit_delay as u64;

        let vtxo_script = DefaultVtxoScript::new(asp, owner, exit_delay).unwrap();

        let spend_info = &vtxo_script.descriptor.spend_info();

        let vtxo_tap_key = spend_info.output_key();

        let network = asp_info.network;

        let ark_address = ArkAddress::new(network, asp, vtxo_tap_key.to_inner());

        Ok((ark_address, vtxo_script))
    }

    pub fn get_offchain_addresses(&self) -> Result<Vec<(ArkAddress, DefaultVtxoScript)>, Error> {
        let address = self.get_offchain_address().unwrap();

        Ok(vec![address])
    }

    pub fn get_onchain_address(&self) -> Result<Address, Error> {
        let pubkey = self.kp.public_key();
        let info = self.asp_info.clone().unwrap();
        let pubkey = bitcoin::key::CompressedPublicKey::try_from(pubkey.to_public_key()).unwrap();
        let address = Address::p2wpkh(&pubkey, info.network);

        Ok(address)
    }

    pub fn get_boarding_address(&self) -> Result<BoardingAddress, Error> {
        let asp_info = self.asp_info.clone().unwrap();

        let network = asp_info.network;

        let boarding_descriptor = asp_info.boarding_descriptor_template;

        let asp_pk: PublicKey = asp_info.pubkey.parse().unwrap();

        let owner_pk = self.kp.public_key();
        let owner_xonly_pk = owner_pk.to_x_only_pubkey();

        let unspendable_key: PublicKey = UNSPENDABLE_KEY.parse().unwrap();
        let unspendable_key = unspendable_key.to_x_only_pubkey();

        let mut pk_map = HashMap::new();

        pk_map.insert("UNSPENDABLE_KEY".to_string(), unspendable_key);
        pk_map.insert("USER_0".to_string(), owner_xonly_pk);
        pk_map.insert("USER_1".to_string(), owner_xonly_pk);
        pk_map.insert("ASP".to_string(), asp_pk.to_x_only_pubkey());

        let mut t = default_vtxo_script::StrPkTranslator { pk_map };

        let real_desc = boarding_descriptor.translate_pk(&mut t).unwrap();

        let address = real_desc.address(network).unwrap();

        let tr = match real_desc.clone() {
            Descriptor::Tr(tr) => tr,
            _ => unreachable!("Descriptor must be taproot"),
        };

        let ark_descriptor = asp_info
            .orig_boarding_descriptor
            .replace("USER", owner_xonly_pk.to_string().as_str());

        Ok(BoardingAddress {
            asp: asp_pk.inner,
            owner: owner_pk,
            address,
            descriptor: tr,
            ark_descriptor,
        })
    }

    pub fn get_boarding_addresses(&self) -> Result<Vec<boarding_address::BoardingAddress>, Error> {
        let address = self.get_boarding_address()?;
        Ok(vec![address])
    }

    pub async fn list_vtxos(&self) -> Result<Vec<ListVtxo>, Error> {
        let addresses = self.get_offchain_addresses()?;

        let mut vtxos = vec![];
        for (address, _) in addresses.into_iter() {
            let list = self.inner.list_vtxos(address).await?;
            vtxos.push(list);
        }

        Ok(vtxos)
    }

    pub async fn spendable_vtxos(&self) -> Result<Vec<(Vec<Vtxo>, DefaultVtxoScript)>, Error> {
        let addresses = self.get_offchain_addresses()?;

        let mut spendable = vec![];
        for (address, script) in addresses.into_iter() {
            let res = self.inner.list_vtxos(address).await?;
            // TODO: Filter expired VTXOs (using `extract_sequence_from_csv_sig_closure`).
            spendable.push((res.spendable, script));
        }

        Ok(spendable)
    }

    // In go client: Balance (minus the on-chain balance, TODO).
    pub async fn offchain_balance(&self) -> Result<Amount, Error> {
        let vec = self.spendable_vtxos().await?;
        let sum = vec
            .iter()
            .flat_map(|(vtxos, _)| vtxos)
            .fold(Amount::ZERO, |acc, x| acc + x.amount);

        Ok(sum)
    }

    // TODO: GetTransactionHistory.

    // In go client: Settle.
    pub async fn board<R>(&self, rng: &mut R) -> Result<(), Error>
    where
        R: Rng + CryptoRng,
    {
        // Get off-chain address and send all funds to this address, no change output 🦄
        let (to_address, _) = self.get_offchain_address()?;

        let (boarding_inputs, vtxo_inputs, total_amount) =
            self.prepare_round_transactions().await?;

        tracing::info!(offchain_adress = %to_address.encode().unwrap(), ?boarding_inputs, "Attempting to board the ark");

        // Joining a round is likely to fail depending on the timing, so we keep retrying.
        //
        // TODO: Consider not retrying on all errors. ATM the retry mechanism is way too quick as
        // well. We should use backoff and only retry on ephemeral errors.
        let txid = loop {
            match self
                .join_next_ark_round(
                    rng,
                    boarding_inputs.clone(),
                    vtxo_inputs.clone(),
                    RoundOutputType::Board {
                        to_address,
                        to_amount: total_amount,
                    },
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

            tokio::time::sleep(Duration::from_secs(1)).await;
        };

        tracing::info!(%txid, "Boarding success");

        Ok(())
    }

    // TODO: SendOffChain, to an off-chain address, using off-chain funds (VTXOs, boarding outputs...).

    // TODO: SendOnChain: to an on-chain address, using on-chain funds.

    // In go client: CollaborativeRedeem.
    pub async fn off_board<R>(
        &self,
        rng: &mut R,
        to_address: Address,
        to_amount: Amount,
    ) -> Result<Txid, Error>
    where
        R: Rng + CryptoRng,
    {
        let (change_address, _) = self.get_offchain_address()?;

        let (boarding_inputs, vtxo_inputs, total_amount) =
            self.prepare_round_transactions().await?;

        let change_amount = total_amount.checked_sub(to_amount).unwrap();

        tracing::info!(
            %to_address,
            %to_amount,
            change_address = %change_address.encode().unwrap(),
            %change_amount,
            ?boarding_inputs,
            "Attempting to off-board the ark"
        );

        // Joining a round is likely to fail depending on the timing, so we keep retrying.
        //
        // TODO: Consider not retrying on all errors. ATM the retry mechanism is way too quick as
        // well. We should use backoff and only retry on ephemeral errors.
        let txid = loop {
            match self
                .join_next_ark_round(
                    rng,
                    boarding_inputs.clone(),
                    vtxo_inputs.clone(),
                    RoundOutputType::OffBoard {
                        to_address: to_address.clone(),
                        to_amount,
                        change_address,
                        change_amount,
                    },
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

            tokio::time::sleep(Duration::from_secs(1)).await;
        };

        tracing::info!(%txid, "Off-boarding success");

        Ok(txid)
    }

    async fn prepare_round_transactions(
        &self,
    ) -> Result<
        (
            Vec<(OutPoint, boarding_address::BoardingAddress)>,
            Vec<(Vtxo, DefaultVtxoScript)>,
            Amount,
        ),
        Error,
    > {
        // Get all known boarding addresses.
        let boarding_addresses = self.get_boarding_addresses().unwrap();

        let mut boarding_inputs: Vec<(OutPoint, boarding_address::BoardingAddress)> = Vec::new();
        let mut total_amount = Amount::ZERO;

        // Find outpoints for each boarding address.
        for boarding_address in boarding_addresses {
            if let Some((outpoint, amount)) = self
                .blockchain
                .find_outpoint(boarding_address.address.clone())
                .await
                .unwrap()
            {
                // TODO: Filter out expired boarding inputs.
                boarding_inputs.push((outpoint, boarding_address));
                total_amount += amount;
            }
        }

        let spendable_vtxos = self.spendable_vtxos().await.unwrap();

        for (vtxos, _) in spendable_vtxos.iter() {
            total_amount += vtxos
                .iter()
                .fold(Amount::ZERO, |acc, vtxo| acc + vtxo.amount)
        }

        let vtxo_inputs = spendable_vtxos
            .into_iter()
            .flat_map(|(vtxos, descriptor)| {
                vtxos
                    .into_iter()
                    .map(|vtxo| (vtxo, descriptor.clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        Ok((boarding_inputs, vtxo_inputs, total_amount))
    }

    #[allow(clippy::too_many_arguments)]
    async fn join_next_ark_round<R>(
        &self,
        rng: &mut R,
        boarding_inputs: Vec<(OutPoint, boarding_address::BoardingAddress)>,
        vtxo_inputs: Vec<(Vtxo, DefaultVtxoScript)>,
        output_type: RoundOutputType,
    ) -> Result<Txid, Error>
    where
        R: Rng + CryptoRng,
    {
        let asp_info = self.asp_info.clone().unwrap();

        // Generate an ephemeral key.
        let ephemeral_kp = Keypair::new(&self.secp, rng);

        let inputs_api = {
            let boarding_inputs = boarding_inputs.clone().into_iter().map(|(o, d)| Input {
                outpoint: Some(Outpoint {
                    txid: o.txid.to_string(),
                    vout: o.vout,
                }),
                descriptor: d.ark_descriptor,
            });

            let vtxo_inputs = vtxo_inputs.clone().into_iter().map(|(o, d)| Input {
                outpoint: o.outpoint.map(|o| Outpoint {
                    txid: o.txid.to_string(),
                    vout: o.vout,
                }),
                descriptor: d.ark_descriptor,
            });

            boarding_inputs.chain(vtxo_inputs).collect()
        };

        let boarding_inputs: Vec<_> = boarding_inputs
            .clone()
            .into_iter()
            .map(|(outpoint, d)| (outpoint, d.forfeit_spend_info()))
            .collect::<Vec<_>>();

        let vtxo_inputs = vtxo_inputs.clone().into_iter().collect::<Vec<_>>();

        let mut client = self.inner.inner.clone().unwrap();
        let response = client
            .register_inputs_for_next_round(RegisterInputsForNextRoundRequest {
                inputs: inputs_api,
                ephemeral_pubkey: Some(ephemeral_kp.public_key().to_string()),
            })
            .await
            .unwrap()
            .into_inner();

        let register_inputs_for_next_round_id = response.id;

        tracing::debug!(
            id = register_inputs_for_next_round_id,
            "Registered for round"
        );

        let mut outputs = vec![];

        match output_type {
            RoundOutputType::Board {
                to_address,
                to_amount,
            } => outputs.push(Output {
                address: to_address.encode().unwrap(),
                amount: to_amount.to_sat(),
            }),
            RoundOutputType::OffBoard {
                to_address,
                to_amount,
                change_address,
                change_amount,
            } => {
                outputs.push(Output {
                    address: to_address.to_string(),
                    amount: to_amount.to_sat(),
                });
                outputs.push(Output {
                    address: change_address.encode().unwrap(),
                    amount: change_amount.to_sat(),
                });
            }
        }

        client
            .register_outputs_for_next_round(RegisterOutputsForNextRoundRequest {
                id: register_inputs_for_next_round_id.clone(),
                outputs,
            })
            .await
            .unwrap();

        // The protocol expects us to ping the ASP every 5 seconds to let the server know that we
        // are still interested in joining the round.
        let (ping_task, _ping_handle) = {
            let mut client = client.clone();
            let round_id = register_inputs_for_next_round_id.clone();
            async move {
                loop {
                    let res = client
                        .ping(PingRequest {
                            payment_id: round_id.clone(),
                        })
                        .await;

                    match res {
                        Ok(msg) => {
                            tracing::trace!("Message via ping: {msg:?}");
                        }
                        Err(ref e) => {
                            tracing::warn!("Error via ping: {e:?}");
                        }
                    }

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
            .unwrap();
        let mut stream = response.into_inner();

        let mut step = RoundStep::Start;

        let asp_pk: secp256k1::PublicKey = asp_info.pubkey.parse().unwrap();
        let sweep_closure = CsvSigClosure {
            pk: asp_pk,
            timeout: asp_info.round_lifetime,
        };

        let sweep_tap_leaf = sweep_closure.leaf();

        let mut round_id: Option<String> = None;
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

                            round_id = Some(e.id.clone());

                            let unsigned_vtxo_tree = e
                                .unsigned_vtxo_tree
                                .expect("we think this should always be some");

                            let secp_zkp = zkp::Secp256k1::new();

                            let mut nonce_tree: Vec<Vec<Option<(MusigSecNonce, MusigPubNonce)>>> =
                                Vec::new();
                            for level in unsigned_vtxo_tree.levels.iter() {
                                let mut nonces_level = vec![];
                                for _ in level.nodes.iter() {
                                    let session_id = MusigSessionId::new(rng);
                                    let extra_rand = rng.gen();

                                    // TODO: Revisit nonce generation, because this is something
                                    // that we could mess up in a non-obvious way.
                                    let (nonce_sk, nonce_pk) = new_musig_nonce_pair(
                                        &secp_zkp,
                                        session_id,
                                        None,
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
                            let mut cosigner_pks =
                                cosigner_pks.clone().expect("To have received them");
                            let mut our_nonce_tree =
                                our_nonce_tree.take().expect("To have generated them");

                            cosigner_pks.sort_by_key(|k| k.serialize());

                            let mut key_agg_cache =
                                MusigKeyAggCache::new(&self.secp_zkp, &cosigner_pks);

                            let sweep_tap_tree = {
                                let (script, version) = sweep_tap_leaf.as_script().unwrap();

                                TaprootBuilder::new()
                                    .add_leaf_with_ver(0, ScriptBuf::from(script), version)
                                    .unwrap()
                                    .finalize(&self.secp, from_zkp_xonly(key_agg_cache.agg_pk()))
                            }
                            .unwrap();

                            let tweak = zkp::SecretKey::from_slice(
                                sweep_tap_tree.tap_tweak().as_byte_array(),
                            )
                            .unwrap();

                            key_agg_cache
                                .pubkey_xonly_tweak_add(&self.secp_zkp, tweak)
                                .unwrap();

                            let ephemeral_kp = zkp::Keypair::from_seckey_slice(
                                &self.secp_zkp,
                                &ephemeral_kp.secret_bytes(),
                            )
                            .unwrap();

                            let mut sig_tree: Vec<Vec<MusigPartialSignature>> = Vec::new();
                            for (i, level) in vtxo_tree.levels.iter().enumerate() {
                                let mut sigs_level = Vec::new();
                                for (j, node) in level.nodes.iter().enumerate() {
                                    tracing::debug!(i, j, ?node, "Generating partial signature");

                                    let nonce = nonce_tree[i][j];

                                    // Equivalent to parsing the individual `MusigAggNonce` from a
                                    // slice.
                                    let agg_nonce = MusigAggNonce::new(&self.secp_zkp, &[nonce]);

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

                                    // NOTE: It seems like we are doing this correctly (at least for
                                    // the root VTXO).
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

                                    // Here we are generating a key spend sighash, because the VTXO
                                    // tree outputs are signed by all parties with a VTXO in this
                                    // new round, so we use a musig key spend to efficiently
                                    // coordinate all the parties.
                                    let tap_sighash = SighashCache::new(tx)
                                        .taproot_key_spend_signature_hash(
                                            VTXO_INPUT_INDEX,
                                            &prevouts,
                                            bitcoin::TapSighashType::Default,
                                        )
                                        .unwrap();

                                    let msg = zkp::Message::from_digest(
                                        tap_sighash.to_raw_hash().to_byte_array(),
                                    );

                                    let nonce_sk = our_nonce_tree[i][j].take().unwrap().0;

                                    let sig = MusigSession::new(
                                        &self.secp_zkp,
                                        &key_agg_cache,
                                        agg_nonce,
                                        msg,
                                    )
                                    .partial_sign(
                                        &self.secp_zkp,
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
                            if step != RoundStep::RoundSigningNoncesGenerated {
                                continue;
                            }
                            tracing::debug!(?e, "Round finalization started");

                            let signed_forfeit_psbts = self
                                .create_and_sign_forfeit_txs(
                                    vtxo_inputs.clone(),
                                    e.connectors,
                                    e.min_relay_fee_rate,
                                )
                                .unwrap();

                            let base64 = base64::engine::GeneralPurpose::new(
                                &base64::alphabet::STANDARD,
                                base64::engine::GeneralPurposeConfig::new(),
                            );

                            let mut round_psbt = {
                                let psbt = base64.decode(&e.round_tx).unwrap();

                                Psbt::deserialize(&psbt).unwrap()
                            };

                            let prevouts = round_psbt
                                .inputs
                                .iter()
                                .filter_map(|i| i.witness_utxo.clone())
                                .collect::<Vec<_>>();

                            // Sign round transaction inputs that belong to us. For every output we
                            // are boarding, we look through the round transaction inputs to find a
                            // matching input.
                            for (boarding_outpoint, (forfeit_script, forfeit_control_block)) in
                                boarding_inputs.iter()
                            {
                                for (i, input) in round_psbt.inputs.iter_mut().enumerate() {
                                    let previous_outpoint =
                                        round_psbt.unsigned_tx.input[i].previous_output;

                                    if &previous_outpoint == boarding_outpoint {
                                        // In the case of a boarding output, we are actually using a
                                        // script spend path.

                                        let leaf_version = forfeit_control_block.leaf_version;
                                        input.tap_scripts = BTreeMap::from_iter([(
                                            forfeit_control_block.clone(),
                                            (forfeit_script.clone(), leaf_version),
                                        )]);

                                        let prevouts = Prevouts::All(&prevouts);

                                        let leaf_hash =
                                            TapLeafHash::from_script(forfeit_script, leaf_version);

                                        let tap_sighash =
                                            SighashCache::new(&round_psbt.unsigned_tx)
                                                .taproot_script_spend_signature_hash(
                                                    i,
                                                    &prevouts,
                                                    leaf_hash,
                                                    bitcoin::TapSighashType::Default,
                                                )
                                                .unwrap();

                                        let msg = secp256k1::Message::from_digest(
                                            tap_sighash.to_raw_hash().to_byte_array(),
                                        );

                                        let sig =
                                            self.secp.sign_schnorr_no_aux_rand(&msg, &self.kp);
                                        let pk = self.kp.x_only_public_key().0;

                                        if self.secp.verify_schnorr(&sig, &msg, &pk).is_err() {
                                            tracing::error!(
                                                "Failed to verify own round TX signature"
                                            );

                                            return Err(Error::Unknown);
                                        }

                                        let sig = taproot::Signature {
                                            signature: sig,
                                            sighash_type: TapSighashType::Default,
                                        };

                                        input.tap_script_sigs =
                                            BTreeMap::from_iter([((pk, leaf_hash), sig)]);
                                    }
                                }
                            }

                            let signed_forfeit_psbts = signed_forfeit_psbts
                                .into_iter()
                                .map(|psbt| base64.encode(psbt.serialize()))
                                .collect();
                            let signed_round_psbt = base64.encode(round_psbt.serialize());

                            client
                                .submit_signed_forfeit_txs(SubmitSignedForfeitTxsRequest {
                                    signed_forfeit_txs: signed_forfeit_psbts,
                                    signed_round_tx: Some(signed_round_psbt),
                                })
                                .await
                                .unwrap();

                            step = step.next();
                        }
                        Some(get_event_stream_response::Event::RoundFinalized(e)) => {
                            if step != RoundStep::RoundFinalization {
                                continue;
                            }

                            let txid = e.round_txid.parse().unwrap();

                            tracing::info!(round_id = e.id, %txid, "Round finalized");

                            return Ok(txid);
                        }
                        Some(get_event_stream_response::Event::RoundFailed(e)) => {
                            if Some(&e.id) == round_id.as_ref() {
                                tracing::error!(
                                    round_id = e.id,
                                    reason = e.reason,
                                    "Failed registering in round"
                                );

                                // TODO: Return a different error (and in many, many other places).
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

    // In go client: SendAsync.
    pub async fn send_oor(&self, address: ArkAddress, amount: Amount) -> Result<Txid, Error> {
        // 1. get spendable VTXOs & script/descriptor for each VTXO
        let spendable_vtxos_and_script = self.spendable_vtxos().await?;

        // 2. run coin selection algorithm on candidates
        let spendable_vtxos_only = spendable_vtxos_and_script
            .iter()
            .flat_map(|(vtxos, _)| vtxos.clone())
            .collect::<Vec<_>>();

        let (_, selected_coins, change_amount) = coin_select(
            vec![],
            spendable_vtxos_only,
            amount,
            self.asp_info.clone().unwrap().dust,
            true,
        )?;

        let mut change_output = None;
        if change_amount > Amount::ZERO {
            // 3. get new change address for sender
            let (change_address, _) = self.get_offchain_address()?;
            change_output.replace((change_address, change_amount));
        }

        let selected_coins =
            selected_coins
                .into_iter()
                .map(|coin| {
                    let script = spendable_vtxos_and_script.clone().into_iter().find_map(
                        |(vtxos, script)| {
                            if vtxos.contains(&coin) {
                                Some(script)
                            } else {
                                None
                            }
                        },
                    );
                    (coin, script.unwrap())
                })
                .collect::<Vec<(_, _)>>();

        let inputs = selected_coins
            .iter()
            .map(|(vtxo, script)| {
                let (forfeit_script, control_block) = script.forfeit_spend_info();
                let mut leaf_hash =
                    TapLeafHash::from_script(&forfeit_script, control_block.leaf_version)
                        .to_byte_array();

                // The ASP reverses this for some reason.
                leaf_hash.reverse();

                AsyncPaymentInput {
                    input: Some(Input {
                        outpoint: vtxo.outpoint.map(|outpoint| Outpoint {
                            txid: outpoint.txid.to_string(),
                            vout: outpoint.vout,
                        }),
                        descriptor: script.ark_descriptor.clone(),
                    }),
                    forfeit_leaf_hash: leaf_hash.to_lower_hex_string(),
                }
            })
            .collect::<Vec<_>>();

        let mut outputs = vec![Output {
            address: address.encode().unwrap(),
            amount: amount.to_sat(),
        }];

        if let Some((change_address, change_amount)) = change_output {
            outputs.push(Output {
                address: change_address.encode().unwrap(),
                amount: change_amount.to_sat(),
            })
        }

        let mut client = self.inner.inner.clone().unwrap();
        let res = client
            .create_payment(CreatePaymentRequest { inputs, outputs })
            .await
            .unwrap();

        let signed_redeem_psbt = res.into_inner().signed_redeem_tx;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let mut signed_redeem_psbt = {
            let psbt = base64.decode(&signed_redeem_psbt).unwrap();

            Psbt::deserialize(&psbt).unwrap()
        };

        let prevouts = signed_redeem_psbt
            .inputs
            .iter()
            .filter_map(|i| i.witness_utxo.clone())
            .collect::<Vec<_>>();

        // Sign all redeem transaction inputs (could be multiple VTXOs!).
        for (vtxo, vtxo_script) in selected_coins.iter() {
            for (i, psbt_input) in signed_redeem_psbt.inputs.iter_mut().enumerate() {
                let psbt_input_outpoint = signed_redeem_psbt.unsigned_tx.input[i].previous_output;

                let vtxo_outpoint = vtxo.outpoint.expect("outpoint");
                if psbt_input_outpoint == vtxo_outpoint {
                    // In the case of input VTXOs, we are actually using a script spend path.
                    let (forfeit_script, forfeit_control_block) = vtxo_script.forfeit_spend_info();

                    let leaf_version = forfeit_control_block.leaf_version;
                    psbt_input.tap_scripts = BTreeMap::from_iter([(
                        forfeit_control_block,
                        (forfeit_script.clone(), leaf_version),
                    )]);

                    let prevouts = Prevouts::All(&prevouts);

                    let leaf_hash = TapLeafHash::from_script(&forfeit_script, leaf_version);

                    let tap_sighash = SighashCache::new(&signed_redeem_psbt.unsigned_tx)
                        .taproot_script_spend_signature_hash(
                            i,
                            &prevouts,
                            leaf_hash,
                            bitcoin::TapSighashType::Default,
                        )
                        .unwrap();

                    let msg =
                        secp256k1::Message::from_digest(tap_sighash.to_raw_hash().to_byte_array());

                    let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &self.kp);
                    let pk = self.kp.x_only_public_key().0;

                    if self.secp.verify_schnorr(&sig, &msg, &pk).is_err() {
                        tracing::error!("Failed to verify own redeem signature");

                        return Err(Error::Unknown);
                    }

                    let sig = taproot::Signature {
                        signature: sig,
                        sighash_type: TapSighashType::Default,
                    };

                    psbt_input.tap_script_sigs = BTreeMap::from_iter([((pk, leaf_hash), sig)]);
                }
            }
        }

        let txid = signed_redeem_psbt.unsigned_tx.compute_txid();

        let signed_redeem_psbt = base64.encode(signed_redeem_psbt.serialize());

        client
            .complete_payment(CompletePaymentRequest {
                signed_redeem_tx: signed_redeem_psbt,
            })
            .await
            .unwrap();

        Ok(txid)
    }

    // In go client: UnilateralRedeem.
    pub async fn unilateral_off_board(&self) -> Result<(), Error> {
        let base64 = &base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let vtxos = self.spendable_vtxos().await.unwrap();

        let mut client = self.inner.inner.clone().unwrap();

        let mut congestion_trees = HashMap::new();
        let mut redeem_branches = HashMap::new();
        for (vtxo_list, _) in vtxos.into_iter() {
            for vtxo in vtxo_list.into_iter() {
                // TODO: Handle exit for pending changes (taken from go implementation).
                if !vtxo.redeem_tx.is_empty() {
                    continue;
                }

                let round_txid = &vtxo.round_txid;
                let round = client
                    .get_round(GetRoundRequest {
                        txid: round_txid.clone(),
                    })
                    .await
                    .unwrap()
                    .into_inner()
                    .round
                    .unwrap();

                let round_psbt = base64.decode(&round.round_tx).unwrap();
                let round_psbt = Psbt::deserialize(&round_psbt).unwrap();

                if !congestion_trees.contains_key(round_txid) {
                    congestion_trees
                        .insert(round_txid.clone(), round.vtxo_tree.expect("we have one"));
                }

                let congestion_tree = congestion_trees.get(round_txid.as_str()).expect("is there");

                let root = &congestion_tree.levels[0].nodes[0];

                let psbt = base64.decode(&root.tx).unwrap();
                let psbt = Psbt::deserialize(&psbt).unwrap();

                for (_, (script, _)) in psbt.inputs[VTXO_INPUT_INDEX].tap_scripts.iter() {
                    let lifetime = extract_sequence_from_csv_sig_closure(script).unwrap();
                    let _lifetime = match lifetime.to_relative_lock_time().unwrap() {
                        relative::LockTime::Time(time) => {
                            Duration::from_secs(time.value() as u64 * 512)
                        }
                        relative::LockTime::Blocks(_) => {
                            unreachable!("Only seconds timelock is supported");
                        }
                    };

                    let vtxo_txid = vtxo.outpoint.expect("outpoint").txid.to_string();
                    let leaf_node = congestion_tree
                        .levels
                        .last()
                        .expect("at least one")
                        .nodes
                        .iter()
                        .find(|node| node.txid == vtxo_txid)
                        .expect("leaf node");

                    // Build the branch from our VTXO to the root of the VTXO tree.
                    let mut branch = vec![leaf_node];
                    while branch[0].txid != root.txid {
                        let parent_node = congestion_tree
                            .levels
                            .iter()
                            .find_map(|level| {
                                level.nodes.iter().find(|node| node.txid == branch[0].txid)
                            })
                            .expect("parent");

                        branch = [vec![parent_node], branch].concat()
                    }

                    let branch = branch
                        .into_iter()
                        .map(|node| {
                            let psbt = base64.decode(&node.tx).unwrap();
                            Psbt::deserialize(&psbt).unwrap()
                        })
                        .collect::<Vec<_>>();

                    redeem_branches.insert(
                        vtxo_txid,
                        (
                            RedeemBranch {
                                _vtxo: vtxo.clone(),
                                branch,
                                _lifetime,
                            },
                            round_psbt.clone(),
                        ),
                    );
                }
            }
        }

        let mut tx_set = HashSet::new();
        let mut all_txs = Vec::new();
        for (redeem_branch, round_psbt) in redeem_branches.values() {
            let mut psbts_to_broadcast = Vec::new();

            // We start from the bottom so that we can stop looking for parent TXs in the redeem
            // path if we find a transaction on the blockchain.
            for mut psbt in redeem_branch.branch.clone().into_iter().rev() {
                let txid = psbt.unsigned_tx.compute_txid();
                match self.blockchain.find_tx(&txid).await.unwrap() {
                    Some(_) => {
                        tracing::debug!(%txid, "Transaction in redeem path already on chain");

                        // We found all the transactions that need to be broadcast to get our VTXO.
                        break;
                    }
                    None => {
                        let vtxo_previous_output =
                            psbt.unsigned_tx.input[VTXO_INPUT_INDEX].previous_output;

                        let witnes_utxo = {
                            redeem_branch
                                .branch
                                .iter()
                                .chain(std::iter::once(round_psbt))
                                .find_map(|other_psbt| {
                                    (other_psbt.unsigned_tx.compute_txid()
                                        == vtxo_previous_output.txid)
                                        .then_some(
                                            other_psbt.unsigned_tx.output
                                                [vtxo_previous_output.vout as usize]
                                                .clone(),
                                        )
                                })
                        }
                        .expect("witness utxo in path");

                        psbt.inputs[VTXO_INPUT_INDEX].witness_utxo = Some(witnes_utxo);

                        psbts_to_broadcast.push(psbt);
                    }
                }
            }

            // The transactions were inserted from leaf to root, so we must reverse the `Vec` to
            // broadcast transactions in a valid order.
            for psbt in psbts_to_broadcast.into_iter().rev() {
                let mut psbt = psbt.clone();

                let tap_key_sig = match psbt.inputs[VTXO_INPUT_INDEX].tap_key_sig {
                    None => {
                        tracing::error!("Missing taproot key spend signature");

                        return Err(Error::Unknown);
                    }
                    Some(tap_key_sig) => tap_key_sig,
                };

                psbt.inputs[VTXO_INPUT_INDEX].final_script_witness =
                    Some(Witness::p2tr_key_spend(&tap_key_sig));

                let tx = psbt.clone().extract_tx().unwrap();

                let txid = tx.compute_txid();
                if !tx_set.contains(&txid) {
                    tx_set.insert(txid);
                    all_txs.push(tx);
                }
            }
        }

        let all_txs_len = all_txs.len();
        for (i, tx) in all_txs.iter().enumerate() {
            let txid = tx.compute_txid();
            tracing::info!(%txid, "Broadcasting VTXO transaction");

            while let Err(e) = self.blockchain.broadcast(tx).await {
                tracing::warn!(%txid, "Error broadcasting VTXO transaction: {e:?}");

                // TODO: Should only retry specific errors, but the API is too rough atm.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }

            tracing::info!(%txid, i, total_txs = all_txs_len, "Broadcasted VTXO transaction");
        }

        Ok(())
    }

    fn create_and_sign_forfeit_txs(
        &self,
        vtxo_inputs: Vec<(Vtxo, DefaultVtxoScript)>,
        connectors: Vec<String>,
        min_relay_fee_rate_sats_per_kvb: i64,
    ) -> Result<Vec<Psbt>, Error> {
        const FORFEIT_TX_CONNECTOR_INDEX: usize = 0;
        const FORFEIT_TX_VTXO_INDEX: usize = 1;

        let asp_info = self.asp_info.clone().unwrap();

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        // Is there such a thing as a connector TX? I think not! The connector TX is actually a
        // round TX, but here we only care about the connector outputs in it i.e. the dust outputs.
        let connector_psbts = connectors
            .into_iter()
            .map(|psbt| {
                let psbt = base64.decode(&psbt).unwrap();
                Psbt::deserialize(&psbt).unwrap()
            })
            .collect::<Vec<_>>();

        let fee_rate_sats_per_kvb = min_relay_fee_rate_sats_per_kvb as u64;
        let connector_amount = asp_info.dust;

        let forfeit_address = bitcoin::Address::from_str(&asp_info.forfeit_address).unwrap();
        let forfeit_address = forfeit_address.require_network(asp_info.network).unwrap();

        let mut signed_forfeit_psbts = Vec::new();
        for (vtxo, vtxo_descriptor) in vtxo_inputs.iter() {
            let min_relay_fee = self
                .compute_forfeit_min_relay_fee(
                    fee_rate_sats_per_kvb,
                    vtxo_descriptor,
                    forfeit_address.clone(),
                )
                .unwrap();

            let mut connector_inputs = Vec::new();
            for connector_psbt in connector_psbts.iter() {
                let txid = connector_psbt.unsigned_tx.compute_txid();
                for (i, connector_output) in connector_psbt.unsigned_tx.output.iter().enumerate() {
                    if connector_output.value == connector_amount {
                        connector_inputs.push((
                            OutPoint {
                                txid,
                                vout: i as u32,
                            },
                            connector_output,
                        ));
                    }
                }
            }

            let forfeit_output = TxOut {
                value: vtxo.amount + connector_amount - min_relay_fee,
                script_pubkey: forfeit_address.script_pubkey(),
            };

            let mut forfeit_psbts = Vec::new();
            // It seems like we are signing multiple forfeit transactions per VTXO i.e. it seems
            // like the ASP will be able to publish different versions of the same forfeit
            // transaction. This might be useful because it gives the ASP more flexibility?
            for (connector_outpoint, connector_output) in connector_inputs.into_iter() {
                let mut forfeit_psbt = Psbt::from_unsigned_tx(Transaction {
                    version: transaction::Version::TWO,
                    lock_time: LockTime::ZERO, // Maybe?
                    input: vec![
                        TxIn {
                            previous_output: connector_outpoint,
                            ..Default::default()
                        },
                        TxIn {
                            previous_output: vtxo.outpoint.expect("outpoint"),
                            ..Default::default()
                        },
                    ],
                    output: vec![forfeit_output.clone()],
                })
                .unwrap();

                forfeit_psbt.inputs[FORFEIT_TX_CONNECTOR_INDEX].witness_utxo =
                    Some(connector_output.clone());

                forfeit_psbt.inputs[FORFEIT_TX_VTXO_INDEX].witness_utxo = Some(TxOut {
                    value: vtxo.amount,
                    script_pubkey: vtxo_descriptor.descriptor.script_pubkey(),
                });

                forfeit_psbt.inputs[FORFEIT_TX_VTXO_INDEX].sighash_type =
                    Some(TapSighashType::Default.into());

                forfeit_psbts.push(forfeit_psbt);
            }

            for forfeit_psbt in forfeit_psbts.iter_mut() {
                let (forfeit_script, forfeit_control_block) = vtxo_descriptor.forfeit_spend_info();

                let leaf_version = forfeit_control_block.leaf_version;
                forfeit_psbt.inputs[FORFEIT_TX_VTXO_INDEX].tap_scripts = BTreeMap::from_iter([(
                    forfeit_control_block,
                    (forfeit_script.clone(), leaf_version),
                )]);

                let prevouts = forfeit_psbt
                    .inputs
                    .iter()
                    .filter_map(|i| i.witness_utxo.clone())
                    .collect::<Vec<_>>();
                let prevouts = Prevouts::All(&prevouts);

                let leaf_hash = TapLeafHash::from_script(&forfeit_script, leaf_version);

                let tap_sighash = SighashCache::new(&forfeit_psbt.unsigned_tx)
                    .taproot_script_spend_signature_hash(
                        FORFEIT_TX_VTXO_INDEX,
                        &prevouts,
                        leaf_hash,
                        bitcoin::TapSighashType::Default,
                    )
                    .unwrap();

                let msg =
                    secp256k1::Message::from_digest(tap_sighash.to_raw_hash().to_byte_array());

                let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &self.kp);
                let pk = self.kp.x_only_public_key().0;

                if self.secp.verify_schnorr(&sig, &msg, &pk).is_err() {
                    tracing::error!("Failed to verify own forfeit signature");

                    return Err(Error::Unknown);
                }

                let sig = taproot::Signature {
                    signature: sig,
                    sighash_type: TapSighashType::Default,
                };

                forfeit_psbt.inputs[FORFEIT_TX_VTXO_INDEX].tap_script_sigs =
                    BTreeMap::from_iter([((pk, leaf_hash), sig)]);

                signed_forfeit_psbts.push(forfeit_psbt.clone());
            }
        }

        Ok(signed_forfeit_psbts)
    }

    fn compute_forfeit_min_relay_fee(
        &self,
        fee_rate_sats_per_kvb: u64,
        vtxo_descriptor: &DefaultVtxoScript,
        forfeit_address: Address,
    ) -> Result<Amount, Error> {
        const INPUT_SIZE: u64 = 32 + 4 + 1 + 4;
        const P2PKH_SCRIPT_SIG_SIZE: u64 = 1 + 73 + 1 + 33;
        const FORFEIT_LEAF_WITNESS_SIZE: u64 = 64 * 2; // 2 signatures for multisig.
        const TAPROOT_BASE_CONTROL_BLOCK_WITNESS_SIZE: u64 = 33;
        const BASE_OUTPUT_SIZE: u64 = 8 + 1;
        const P2PKH_SIZE: u64 = 25;
        const P2SH_SIZE: u64 = 23;
        const P2WKH_SIZE: u64 = 1 + 1 + 20;
        const P2WSH_SIZE: u64 = 1 + 1 + 32;
        const P2TR_SIZE: u64 = 34;
        const P2PKH_OUTPUT_SIZE: u64 = BASE_OUTPUT_SIZE + P2PKH_SIZE;
        const P2SH_OUTPUT_SIZE: u64 = BASE_OUTPUT_SIZE + P2SH_SIZE;
        const P2WKH_OUTPUT_SIZE: u64 = BASE_OUTPUT_SIZE + P2WKH_SIZE;
        const P2WSH_OUTPUT_SIZE: u64 = BASE_OUTPUT_SIZE + P2WSH_SIZE;
        const P2TR_OUTPUT_SIZE: u64 = BASE_OUTPUT_SIZE + P2TR_SIZE;
        const BASE_TX_SIZE: u64 = 4 + 4;

        let n_inputs = 2;
        let n_outputs = 1;
        let mut input_size = 0;
        let mut witness_size = 0;
        let mut output_size = 0;

        // 1 connector input. We use P2PKH for this!
        input_size += INPUT_SIZE + P2PKH_SCRIPT_SIG_SIZE;
        witness_size += 1;

        // 1 VTXO input.
        input_size += INPUT_SIZE;

        let spend_info = &vtxo_descriptor.descriptor.spend_info();
        let ((biggest_script, leaf_version), _) = spend_info
            .script_map()
            .iter()
            .max_by_key(|((script, leaf_version), _)| {
                let control_block = spend_info
                    .control_block(&(script.clone(), *leaf_version))
                    .expect("control block");

                control_block.size() + script.len()
            })
            .expect("at least one");

        let control_block = spend_info
            .control_block(&(biggest_script.clone(), *leaf_version))
            .expect("control block");

        // We add 1 byte for the total number of witness elements.
        //
        // 1 byte for the length of the element plus the element itself.
        let control_block_witness_size = 1
            + TAPROOT_BASE_CONTROL_BLOCK_WITNESS_SIZE
            + 1
            + (biggest_script.len() as u64)
            + 1
            + (control_block.merkle_branch.concat().len() as u64);

        witness_size += FORFEIT_LEAF_WITNESS_SIZE + control_block_witness_size;

        match forfeit_address.address_type() {
            Some(AddressType::P2pkh) => {
                output_size += P2PKH_OUTPUT_SIZE;
            }
            Some(AddressType::P2sh) => {
                output_size += P2SH_OUTPUT_SIZE;
            }
            Some(AddressType::P2wpkh) => {
                output_size += P2WKH_OUTPUT_SIZE;
            }
            Some(AddressType::P2wsh) => {
                output_size += P2WSH_OUTPUT_SIZE;
            }
            Some(AddressType::P2tr) => {
                output_size += P2TR_OUTPUT_SIZE;
            }
            _ => unreachable!("Unless they add new witness versions"),
        }

        let input_count = VarInt(n_inputs).size() as u64;
        let output_count = VarInt(n_outputs).size() as u64;
        let tx_size_stripped = BASE_TX_SIZE + input_count + input_size + output_count + output_size;

        let weight_wu = tx_size_stripped * WITNESS_SCALE_FACTOR as u64;
        let weight_wu = weight_wu + witness_size;

        let weight_vb = weight_wu as f64 / 4.0;

        // 1012 sat/kvb == 1012/4 sat/kwu
        let fee_rate = FeeRate::from_sat_per_kwu(fee_rate_sats_per_kvb / 4);

        let fee = fee_rate.fee_vb(weight_vb.ceil() as u64).expect("amount");

        // FIXME: The `lnd` dependency in go is rounding down and `rust-bitcoin` is rounding up! We
        // just need to upgrade.
        let fee = fee - Amount::ONE_SAT;

        Ok(fee)
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
    use bitcoin::hex::DisplayHex;
    use bitcoin::hex::FromHex;
    use std::sync::Once;
    use zkp::MusigPubNonce;
    use zkp::MusigSecNonce;

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
