# Ark-rs - A rust client library for Ark

## Local dev setup

We use [tokio-prost](https://github.com/tokio-rs/prost) to generate code from proto files. It does not bundle protoc anymore, hence, you'll need to install it yourself (see [here](http://google.github.io/proto-lens/installing-protoc.html)).

### Generate rust files from proto

```bash
RUSTFLAGS="--cfg genproto" cargo build`
```
