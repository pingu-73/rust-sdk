use crate::ark_address::ArkAddress;
use crate::asp::types::Info;
use crate::asp::types::ListVtxo;
use crate::asp::types::Vtxo;
use crate::error::Error;
use crate::generated::ark::v1::ark_service_client::ArkServiceClient;
use crate::generated::ark::v1::GetInfoRequest;
use crate::generated::ark::v1::ListVtxosRequest;
use tonic::transport::Channel;

pub struct Client {
    url: String,
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

        Ok(response.into_inner().try_into()?)
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
}
