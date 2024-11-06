use crate::ark_address::ArkAddress;
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
const BOARDING_DESCRIPTOR_TEMPLATE_MINISCRIPT: &str =
    "tr(UNSPENDABLE_KEY,{and_v(v:pk(USER_0),older(TIMEOUT)),and_v(v:pk(USER_1),pk(ASP))})";

/// The Miniscript descriptor used for the default VTXO.
///
/// We expect the ASP to provide this, but at the moment the ASP does not quite speak Miniscript.
///
/// We use `USER_0` and `USER_1` for the same user key, because `rust-miniscript` does not allow
/// repeating identifiers.
const DEFAULT_VTXO_DESCRIPTOR_TEMPLATE_MINISCRIPT: &str =
    "tr(UNSPENDABLE_KEY,{and_v(v:pk(USER_0),older(TIMEOUT)),and_v(v:pk(USER_1),pk(ASP))})";

const UNSPENDABLE_KEY: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

const BOARDING_REFUND_TIMEOUT: u64 = 604672;

pub struct Client {
    inner: asp::Client,
    name: String,
    kp: Keypair,
    asp_info: Option<asp::Info>,
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

impl Client {
    pub fn new<R>(secp: Secp256k1<All>, rng: &mut R, name: String) -> Self
    where
        R: Rng + CryptoRng,
    {
        let kp = Keypair::new(&secp, rng);

        let inner = asp::Client::new("http://localhost:7070".to_string());

        Self {
            inner,
            name,
            kp,
            asp_info: None,
        }
    }

    pub async fn connect(&mut self) -> Result<(), Error> {
        self.inner.connect().await?;
        let info = self.inner.get_info().await?;

        self.asp_info = Some(info);

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

    fn new_boarding_address(&self) -> Result<Address, Error> {
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

        Ok(address)
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

    fn board(&self, outpoint: OutPoint) -> Result<(), Error> {
        todo!()
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
    use crate::Client;
    use bitcoin::hex::FromHex;
    use bitcoin::key::Secp256k1;
    use bitcoin::Address;
    use bitcoin::Amount;
    use bitcoin::OutPoint;
    use bitcoin::Transaction;
    use bitcoin::Txid;
    use rand::thread_rng;
    use regex::Regex;
    use std::process::Command;

    async fn setup_client(name: String) -> Client {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        let mut client = Client::new(secp, &mut rng, name);

        client.connect().await.unwrap();

        client
    }

    async fn faucet_fund(address: Address, amount: Amount) -> OutPoint {
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

        OutPoint {
            txid,
            vout: vout as u32,
        }
    }

    #[tokio::test]
    pub async fn e2e() {
        let alice = setup_client("alice".to_string()).await;

        // This is just an on-chain address.
        let alice_boarding_address = alice.new_boarding_address().unwrap();

        let boarding_output = faucet_fund(alice_boarding_address, Amount::ONE_BTC).await;

        println!("Boarding output: {boarding_output:?}");

        let offchain_balance = alice.offchain_balance().await.unwrap();

        println!("Alice offchain balance: {offchain_balance}");
    }
}
