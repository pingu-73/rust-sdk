use crate::ark_address::ArkAddress;
use crate::generated::ark::v1::Input;
use crate::generated::ark::v1::Outpoint;
use crate::generated::ark::v1::Output;
use crate::generated::ark::v1::RegisterInputsForNextRoundRequest;
use crate::generated::ark::v1::RegisterOutputsForNextRoundRequest;
use crate::generated::ark::v1::{GetEventStreamRequest, PingRequest};
use bitcoin::key::Keypair;
use bitcoin::key::PublicKey;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::XOnlyPublicKey;
use error::Error;
use miniscript::translate_hash_fail;
use miniscript::Descriptor;
use miniscript::ToPublicKey;
use miniscript::TranslatePk;
use miniscript::Translator;
use rand::CryptoRng;
use rand::Rng;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tonic::codegen::tokio_stream::StreamExt;

pub mod generated {
    #[path = ""]
    pub mod ark {
        #[path = "ark.v1.rs"]
        pub mod v1;
    }
}

pub mod ark_address;
mod asp;
pub mod error;

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

pub struct Client<B> {
    inner: asp::Client,
    name: String,
    kp: Keypair,
    asp_info: Option<asp::Info>,
    blockchain: Arc<B>,
}

#[derive(Clone, Debug)]
pub struct BoardingAddress {
    address: Address,
    descriptor: miniscript::descriptor::Tr<XOnlyPublicKey>,
    pub ark_descriptor: String,
}

#[derive(Debug, Clone)]
pub struct DefaultVtxoScript {
    asp: XOnlyPublicKey,
    owner: XOnlyPublicKey,
    exit_delay: u64,
    descriptor: miniscript::descriptor::Tr<XOnlyPublicKey>,
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

        let mut client = self.inner.inner.clone().unwrap();

        tokio::spawn({
            let mut client = client.clone();
            async move {
                let response = client
                    .get_event_stream(GetEventStreamRequest {})
                    .await
                    .unwrap();

                let mut streaming = response.into_inner();
                while let Some(event) = streaming.next().await {
                    tracing::debug!("Received new event {event:?}");
                }
                tracing::error!("Event stream terminated");
            }
        });

        // tokio::spawn(async move {
        //     loop {
        //         let response = client
        //             .ping(PingRequest {
        //                 payment_id: "WTF".to_string(),
        //             })
        //             .await
        //             .unwrap();
        //         tracing::debug!(?response, "Sent ping");
        //
        //         tokio::time::sleep(Duration::from_millis(100)).await
        //     }
        // });

        Ok(())
    }

    // At the moment we are always generating the same address.
    fn get_offchain_address(&self) -> Result<ArkAddress, Error> {
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

    fn get_offchain_addresses(&self) -> Result<Vec<ArkAddress>, Error> {
        let address = self.get_offchain_address().unwrap();

        Ok(vec![address])
    }

    fn get_boarding_address(&self) -> Result<BoardingAddress, Error> {
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

    fn get_boarding_addresses(&self) -> Result<Vec<BoardingAddress>, Error> {
        let address = self.get_boarding_address()?;
        Ok(vec![address])
    }

    async fn offchain_balance(&self) -> Result<Amount, Error> {
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

    async fn board<R>(&self, secp: &Secp256k1<All>, rng: &mut R) -> Result<(), Error>
    where
        R: Rng + CryptoRng,
    {
        // 1. get all known boarding addresses
        let boarding_addresses = self.get_boarding_addresses()?;

        let mut outpoints: Vec<(OutPoint, BoardingAddress)> = vec![];
        let mut total_amount = Amount::ZERO;
        // 2. find outpoints for each address
        for boarding_address in boarding_addresses {
            let (out_point, amount) = self
                .blockchain
                .find_outpoint(boarding_address.address.clone())
                .await?;

            // 3. TODO: check if outpoint has not expired yet and filter it out
            outpoints.push((out_point, boarding_address));
            total_amount += amount;
        }

        // 5. get off-chain address and send all funds to this address, no change outpoint 🦄
        let address = self.get_offchain_address()?;

        // 6. get ephemeral key
        let key = Keypair::new(secp, rng);
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

        // TODO: move this into our api layer
        let mut client = self.inner.inner.clone().unwrap();
        let response = client
            .register_inputs_for_next_round(RegisterInputsForNextRoundRequest {
                inputs,
                ephemeral_pubkey: Some(key.public_key().to_string()),
            })
            .await
            .unwrap()
            .into_inner();

        tracing::debug!(id = response.id, "Registered for round");

        client
            .register_outputs_for_next_round(RegisterOutputsForNextRoundRequest {
                id: response.id.clone(),
                outputs: vec![Output {
                    address: address.encode()?,
                    amount: total_amount.to_sat(),
                }],
            })
            .await
            .unwrap();

        let response = client
            .ping(PingRequest {
                payment_id: response.id,
            })
            .await
            .unwrap();

        tracing::debug!(?response, "REceived ping response");

        Ok(())
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

#[cfg(test)]
pub mod tests {
    use crate::error::Error;
    use crate::Blockchain;
    use crate::Client;
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
    use std::sync::Mutex;
    use std::sync::{Arc, Once};
    use std::time::Duration;

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

            let tx = Vec::from_hex(dbg!(tx.trim())).unwrap();
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
            Ok(value.clone())
        }
    }

    async fn setup_client(name: String, kp: Keypair, nigiri: Arc<Nigiri>) -> Client<Nigiri> {
        let mut client = Client::new(name, kp, nigiri);

        client.connect().await.unwrap();

        client
    }

    #[tokio::test]
    pub async fn e2e() {
        init_tracing();
        let nigiri = Arc::new(Nigiri::new());

        let secp = Secp256k1::new();
        let mut rng = thread_rng();

        let key = SecretKey::new(&mut rng);
        let keypair = Keypair::from_secret_key(&secp, &key);

        let alice = setup_client("alice".to_string(), keypair, nigiri.clone()).await;

        // This is just an on-chain address.
        let alice_boarding_address = alice.get_boarding_address().unwrap();

        let boarding_output = nigiri
            .faucet_fund(alice_boarding_address.address, Amount::ONE_BTC)
            .await;

        tracing::debug!("Boarding output: {boarding_output:?}");

        let offchain_balance = alice.offchain_balance().await.unwrap();

        tracing::debug!("Alice offchain balance: {offchain_balance}");

        alice.board(&secp, &mut rng).await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
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
