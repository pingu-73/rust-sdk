#![allow(clippy::unwrap_used)]

use ark_rs::boarding_output::BoardingOutput;
use ark_rs::error::Error;
use ark_rs::wallet::Persistence;
use ark_rs::Blockchain;
use ark_rs::Client;
use ark_rs::ExplorerUtxo;
use ark_rs::OfflineClient;
use bitcoin::hex::FromHex;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::Txid;
use regex::Regex;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Once;
use tokio::sync::Mutex;

pub struct Nigiri {
    esplora_client: esplora_client::BlockingClient,
}

impl Nigiri {
    pub fn new() -> Self {
        let builder = esplora_client::Builder::new("http://localhost:30000");
        let esplora_client = builder.build_blocking();

        Self { esplora_client }
    }

    pub async fn faucet_fund(&self, address: &Address, amount: Amount) -> OutPoint {
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

        // Wait for output to be confirmed.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        OutPoint {
            txid,
            vout: vout as u32,
        }
    }

    async fn _mine(&self, n: u32) {
        for _ in 0..n {
            self.faucet_fund(
                &Address::from_str("bcrt1q8frde3yn78tl9ecgq4anlz909jh0clefhucdur")
                    .unwrap()
                    .assume_checked(),
                Amount::from_sat(10_000),
            )
            .await;
        }
    }
}

impl Default for Nigiri {
    fn default() -> Self {
        Self::new()
    }
}

impl Blockchain for Nigiri {
    async fn find_outpoints(&self, address: &Address) -> Result<Vec<ExplorerUtxo>, Error> {
        let script_pubkey = address.script_pubkey();
        let txs = self
            .esplora_client
            .scripthash_txs(&script_pubkey, None)
            .unwrap();

        let outputs = txs
            .into_iter()
            .flat_map(|tx| {
                let txid = tx.txid;
                let confirmation_blocktime = tx.status.block_time;
                tx.vout
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v.scriptpubkey == script_pubkey)
                    .map(|(i, v)| ExplorerUtxo {
                        outpoint: OutPoint {
                            txid,
                            vout: i as u32,
                        },
                        amount: Amount::from_sat(v.value),
                        confirmation_blocktime,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut utxos = Vec::new();
        for output in outputs.iter() {
            let outpoint = output.outpoint;
            let status = self
                .esplora_client
                .get_output_status(&outpoint.txid, outpoint.vout as u64)
                .unwrap();

            match status {
                Some(esplora_client::OutputStatus { spent: false, .. }) | None => {
                    utxos.push(*output);
                }
                // Ignore spent transaction outputs
                Some(esplora_client::OutputStatus { spent: true, .. }) => {}
            }
        }

        Ok(utxos)
    }

    async fn find_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        let tx = self.esplora_client.get_tx(txid).unwrap();

        Ok(tx)
    }

    // TODO: Make sure we return a proper error here, so that we can retry if we encounter a
    // `bad-txns-inputs-missingorspent` error.
    async fn broadcast(&self, tx: &Transaction) -> Result<(), Error> {
        self.esplora_client.broadcast(tx).unwrap();

        Ok(())
    }
}

#[derive(Default)]
pub struct InMemoryDb {
    boarding_outputs: Vec<(SecretKey, BoardingOutput)>,
}

impl Persistence for InMemoryDb {
    fn save_boarding_address(
        &mut self,
        sk: SecretKey,
        boarding_address: BoardingOutput,
    ) -> Result<(), Error> {
        self.boarding_outputs.push((sk, boarding_address));
        Ok(())
    }

    fn load_boarding_addresses(&self) -> Result<Vec<BoardingOutput>, Error> {
        Ok(self
            .boarding_outputs
            .clone()
            .into_iter()
            .map(|(_, address)| address)
            .collect())
    }

    fn sk_for_boarding_address(
        &self,
        boarding_address: &BoardingOutput,
    ) -> Result<SecretKey, Error> {
        let maybe_sk = self.boarding_outputs.iter().find_map(|(sk, b)| {
            if b == boarding_address {
                Some(*sk)
            } else {
                None
            }
        });
        let secret_key = maybe_sk.unwrap();
        Ok(secret_key)
    }
}

pub async fn set_up_client(
    name: String,
    kp: Keypair,
    nigiri: Arc<Nigiri>,
    secp: Secp256k1<All>,
) -> (
    Client<Nigiri, ark_bdk_wallet::Wallet<InMemoryDb>>,
    Arc<Mutex<ark_bdk_wallet::Wallet<InMemoryDb>>>,
) {
    let db = InMemoryDb::default();
    let wallet =
        ark_bdk_wallet::Wallet::new(kp, secp, Network::Regtest, "http://localhost:3000", db)
            .unwrap();
    let wallet = Arc::new(Mutex::new(wallet));

    let client = OfflineClient::new(name, kp, nigiri, wallet.clone())
        .connect()
        .await
        .unwrap();

    (client, wallet)
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
