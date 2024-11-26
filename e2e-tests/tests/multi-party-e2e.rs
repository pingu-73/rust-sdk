use ark_bdk_wallet::Wallet;
use ark_rs::boarding_output::BoardingOutput;
use ark_rs::error::Error;
use ark_rs::wallet::BoardingWallet;
use ark_rs::wallet::Persistence;
use ark_rs::Blockchain;
use ark_rs::Client;
use bitcoin::hex::FromHex;
use bitcoin::key::Keypair;
use bitcoin::key::PublicKey;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::Txid;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::SeedableRng;
use regex::Regex;
use std::collections::HashMap;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Once;
use tokio::sync::Mutex;
use tokio::try_join;

#[tokio::test]
pub async fn multi_party_e2e() {
    init_tracing();
    let nigiri = Arc::new(Nigiri::new());

    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    let alice_key = SecretKey::new(&mut rng);
    let alice_keypair = Keypair::from_secret_key(&secp, &alice_key);
    let (alice, alice_wallet) = setup_client(
        "alice".to_string(),
        alice_keypair,
        nigiri.clone(),
        secp.clone(),
    )
    .await;

    let bob_key = SecretKey::new(&mut rng);
    let bob_keypair = Keypair::from_secret_key(&secp, &bob_key);
    let (bob, bob_wallet) =
        setup_client("bob".to_string(), bob_keypair, nigiri.clone(), secp.clone()).await;

    let claire_key = SecretKey::new(&mut rng);
    let claire_keypair = Keypair::from_secret_key(&secp, &claire_key);
    let (claire, claire_wallet) = setup_client(
        "claire".to_string(),
        claire_keypair,
        nigiri.clone(),
        secp.clone(),
    )
    .await;

    let alice_boarding_address = new_boarding_address(&alice, &alice_wallet).await;
    let bob_boarding_address = new_boarding_address(&bob, &bob_wallet).await;
    let claire_boarding_address = new_boarding_address(&claire, &claire_wallet).await;

    let alice_boarding_output = nigiri
        .faucet_fund(alice_boarding_address.address(), Amount::ONE_BTC)
        .await;

    let bob_initial_balance = Amount::ONE_BTC;
    let bob_boarding_output = nigiri
        .faucet_fund(bob_boarding_address.address(), bob_initial_balance)
        .await;
    let claire_boarding_output = nigiri
        .faucet_fund(claire_boarding_address.address(), Amount::ONE_BTC)
        .await;

    tracing::debug!("Boarding output alice: {alice_boarding_output:?}");
    tracing::debug!("Boarding output bob: {bob_boarding_output:?}");
    tracing::debug!("Boarding output claire: {claire_boarding_output:?}");

    let alice_offchain_balance = alice.offchain_balance().await.unwrap();
    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let claire_offchain_balance = claire.offchain_balance().await.unwrap();
    tracing::debug!("Pre boarding: Alice offchain balance: {alice_offchain_balance}");
    tracing::debug!("Pre boarding: Bob offchain balance: {bob_offchain_balance}");
    tracing::debug!("Pre boarding: Claire offchain balance: {claire_offchain_balance}");

    let alice_task = tokio::spawn(async move {
        let mut rng = StdRng::from_entropy();
        alice.board(&mut rng).await.unwrap();
        alice
    });

    let bob_task = tokio::spawn(async move {
        let mut rng = StdRng::from_entropy();
        bob.board(&mut rng).await.unwrap();
        bob
    });

    let claire_task = tokio::spawn(async move {
        let mut rng = StdRng::from_entropy();
        claire.board(&mut rng).await.unwrap();
        claire
    });

    let (alice, bob, claire) = try_join!(alice_task, bob_task, claire_task).unwrap();

    let alice_offchain_balance = alice.offchain_balance().await.unwrap();
    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let claire_offchain_balance = claire.offchain_balance().await.unwrap();
    tracing::debug!("Post boarding: Alice offchain balance: {alice_offchain_balance}");
    tracing::debug!("Post boarding: Bob offchain balance: {bob_offchain_balance}");
    tracing::debug!("Post boarding: Claire offchain balance: {claire_offchain_balance}");

    let (bob_offchain_address, _) = bob.get_offchain_address().unwrap();
    let amount = Amount::from_sat(100_000);

    bob.list_vtxos().await.unwrap();

    let alice_task = tokio::spawn(async move {
        tracing::debug!("Alice is sending {amount} to Bob offchain...");
        alice.send_oor(bob_offchain_address, amount).await.unwrap();
        alice
    });
    let claire_task = tokio::spawn(async move {
        tracing::debug!("Claire is sending {amount} to Bob offchain...");
        claire.send_oor(bob_offchain_address, amount).await.unwrap();
        claire
    });

    let (_alice, _claire) = try_join!(alice_task, claire_task).unwrap();

    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let bob_vtxos = bob.list_vtxos().await.unwrap();
    tracing::debug!(
        ?bob_vtxos,
        "Post payment: Bob offchain balance: {bob_offchain_balance}"
    );

    assert_eq!(bob_offchain_balance, bob_initial_balance + amount * 2);
}

async fn new_boarding_address(
    client: &Client<Nigiri, Wallet<InMemoryDb>>,
    alice_wallet: &Arc<Mutex<Wallet<InMemoryDb>>>,
) -> BoardingOutput {
    let alice_asp_info = client.asp_info.clone().unwrap();
    let asp_pk: PublicKey = alice_asp_info.pubkey.parse().unwrap();
    let (asp_pk, _) = asp_pk.inner.x_only_public_key();

    let mut wallet = alice_wallet.lock().await;
    wallet
        .new_boarding_address(
            asp_pk,
            alice_asp_info.round_lifetime as u32,
            alice_asp_info.boarding_descriptor_template,
            alice_asp_info.network,
        )
        .unwrap()
}

struct Nigiri {
    utxos: Mutex<HashMap<bitcoin::Address, (OutPoint, Amount)>>,
    esplora_client: esplora_client::BlockingClient,
}

impl Nigiri {
    pub fn new() -> Self {
        let builder = esplora_client::Builder::new("http://localhost:30000");
        let esplora_client = builder.build_blocking();

        Self {
            utxos: Mutex::new(HashMap::new()),
            esplora_client,
        }
    }

    async fn faucet_fund(&self, address: &Address, amount: Amount) -> OutPoint {
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
        let mut guard = self.utxos.lock().await;
        guard.insert(address.clone(), (point, amount));

        point
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

impl Blockchain for Nigiri {
    async fn find_outpoint(&self, address: &Address) -> Result<Option<(OutPoint, Amount)>, Error> {
        let guard = self.utxos.lock().await;
        let value = guard.get(address);
        if let Some((outpoint, _amount)) = value {
            let option = self
                .esplora_client
                .get_output_status(&outpoint.txid, outpoint.vout as u64)
                .unwrap();
            match option {
                None => {
                    tracing::error!("No status for outpoint, taking cached results instead");
                }
                Some(status) => {
                    tracing::debug!(?status, "Status of outpoint");

                    if status.spent {
                        return Ok(None);
                    }
                }
            }
        }

        Ok(value.copied())
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

#[derive(Default, Clone)]
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

async fn setup_client(
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
        ark_bdk_wallet::Wallet::new(kp, secp, Network::Regtest, "http://localhost:3000", db);
    let wallet = Arc::new(Mutex::new(wallet));
    let mut client = Client::new(name, kp, nigiri, wallet.clone());

    client.connect().await.unwrap();

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
