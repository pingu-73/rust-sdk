set dotenv-load

## ------------------------
## Code quality functions
## ------------------------

fmt:
    dprint fmt

clippy:
    cargo clippy --all-targets --all-features -- -D warnings
