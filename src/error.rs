// TODO: Implement Display and use `thiserror`.
#[derive(Debug)]
pub enum Error {
    AspNotConnected,
    InvalidResponseType,
    Unknown,
}
