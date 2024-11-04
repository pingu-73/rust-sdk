use crate::generated::ark::v1::admin_service_client::AdminServiceClient;
use crate::generated::ark::v1::ark_service_client::ArkServiceClient;
use crate::generated::ark::v1::GetInfoRequest;
use anyhow::Result;
use bitcoin::Address;
use bitcoin::OutPoint;
use std::str::FromStr;

pub mod generated {
    #[path = ""]
    pub mod ark {
        #[path = "ark.v1.rs"]
        pub mod v1;
    }
}

struct ArkClient {
    name: String,
}

impl ArkClient {
    fn new_boarding_address(&self) -> Result<Address> {
        // TODO: implement me
        let address = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k")?;
        Ok(address.assume_checked())
    }
    fn new_offchain_address(&self) -> Result<Address> {
        // TODO: implement me
        let address = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k")?;
        Ok(address.assume_checked())
    }
    fn board(&self, outpouint: OutPoint) -> Result<()> {
        // TODO: implement me
        Ok(())
    }

    pub fn new(name: String) -> Self {
        Self { name }
    }

    pub async fn connect(&self) -> Result<()> {
        let mut client = ArkServiceClient::connect("http://localhost:7070")
            .await
            .unwrap();
        let response = client.get_info(GetInfoRequest {}).await?;
        let response = response.into_inner();
        dbg!(response);
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use crate::ArkClient;
    use anyhow::Result;
    use bitcoin::hashes::Hash;
    use bitcoin::Address;
    use bitcoin::Amount;
    use bitcoin::OutPoint;
    use bitcoin::Txid;

    async fn setup_client(name: String) -> Result<ArkClient> {
        let client = ArkClient::new(name);
        // setup the client
        client.connect().await?;
        Ok(client)
    }
    async fn faucet_fund(address: Address, amount: Amount) -> Result<OutPoint> {
        // TODO: implement me
        Ok(OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        })
    }

    #[tokio::test]
    pub async fn test() {
        let alice = setup_client("alice".to_string()).await.unwrap();
        let bob = setup_client("bob".to_string()).await.unwrap();

        // this is just an on-chain address
        let alice_on_chain_address = alice.new_boarding_address().unwrap();

        let txid = faucet_fund(alice_on_chain_address, Amount::ONE_BTC)
            .await
            .unwrap();

        let vtxo = alice.board(txid).unwrap();

        let alice_off_chain_address = bob.new_offchain_address().unwrap();
    }
}
