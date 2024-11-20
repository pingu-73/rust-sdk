set dotenv-load

clarkd_url := "http://localhost:7070"
clarkd_logs := "$PWD/clarkd.log"

## ------------------------
## Code quality functions
## ------------------------

fmt:
    dprint fmt

clippy:
    cargo clippy --all-targets --all-features -- -D warnings

## -----------------
## Code generation
## -----------------

# Generate GRPC code. Modify proto files before calling this.
gen-grpc:
    #!/usr/bin/env bash

    RUSTFLAGS="--cfg genproto" cargo build

## -------------------------
## Local development setup
## -------------------------

# Set up `clarkd` so that we can run the client e2e tests against it.
clarkd-setup:
    #!/usr/bin/env bash

    set -euxo pipefail

    just clarkd-run

    echo "Started clarkd"

    just clarkd-init

    just clarkd-fund 10

# Start `clarkd` binary.
clarkd-run:
    #!/usr/bin/env bash

    set -euxo pipefail

    make -C $CLARKD_DIR run &> {{clarkd_logs}} &

    just _wait-until-clarkd-is-ready

    echo "Clarkd started. Find the logs in {{clarkd_logs}}"

# Initialize `clarkd` by creating and unlocking a new wallet.
clarkd-init:
    #!/usr/bin/env bash

    set -euxo pipefail

    seed=$(curl -s {{clarkd_url}}/v1/admin/wallet/seed | jq .seed -r)

    curl -s --data-binary '{"seed": "$seed", "password": "password"}' -H "Content-Type: application/json" {{clarkd_url}}/v1/admin/wallet/create

    echo "Created clarkd wallet"

    curl -s --data-binary '{"password" : "password"}' -H "Content-Type: application/json" {{clarkd_url}}/v1/admin/wallet/unlock

    echo "Unlocked clarkd wallet"

    just _wait-until-clarkd-wallet-is-ready

# Fund `clarkd`'s wallet.
clarkd-fund n:
    #!/usr/bin/env bash

    set -euxo pipefail

    for i in {1..{{n}}}; do
        address=$(curl -s {{clarkd_url}}/v1/admin/wallet/address | jq .address -r)

        echo "Funding clarkd wallet (Iteration $i)"

        nigiri faucet "$address" 10
    done

# Stop `clarkd` binary and delete logs.
clarkd-kill:
    pkill -9 arkd && echo "Stopped clarkd" || echo "Clarkd not running, skipped"
    [ ! -e "{{clarkd_logs}}" ] || mv -f {{clarkd_logs}} {{clarkd_logs}}.old

# Wipe `clarkd` data directory.
clarkd-wipe:
    rm -rf $CLARKD_DIR/data

_wait-until-clarkd-is-ready:
    #!/usr/bin/env bash

    echo "Waiting for clarkd to be ready..."

    for ((i=0; i<30; i+=1)); do
      status_code=$(curl -o /dev/null -s -w "%{http_code}" {{clarkd_url}}/v1/admin/wallet/seed)

      if [ "$status_code" -eq 200 ]; then
        echo "clarkd is ready!"
        exit 0
      fi
      sleep 1
    done

    echo "clarkd was not ready in time"

    exit 1

_wait-until-clarkd-wallet-is-ready:
    #!/usr/bin/env bash

    echo "Waiting for clarkd wallet to be ready..."

    for ((i=0; i<30; i+=1)); do
      res=$(curl -s {{clarkd_url}}/v1/admin/wallet/status)

      if echo "$res" | jq -e '.initialized == true and .unlocked == true and .synced == true' > /dev/null; then
        echo "clarkd wallet is ready!"
        exit 0
      fi
      sleep 1
    done

    echo "clarkd wallet was not ready in time"

    exit 1
