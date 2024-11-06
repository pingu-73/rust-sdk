set dotenv-load

## ------------------------
## Code quality functions
## ------------------------

fmt:
    dprint fmt

clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Set up `clarkd` so that we can run the client e2e tests against it.
clarkd-setup:
    #!/usr/bin/env bash

    set -euxo pipefail
    #
    #    docker compose -f $CLARKD_COMPOSE_FILE up -d --build
    #
    #    just _wait-until-clarkd-is-ready

    echo "Started clarkd"

    seed=$(curl -s http://localhost:7070/v1/admin/wallet/seed | jq .seed -r)

    curl -s --data-binary '{"seed": "$seed", "password": "password"}' -H "Content-Type: application/json" http://localhost:7070/v1/admin/wallet/create

    echo "Created clarkd wallet"

    curl -s --data-binary '{"password" : "password"}' -H "Content-Type: application/json" http://localhost:7070/v1/admin/wallet/unlock

    echo "Unlocked clarkd wallet"

    just _wait-until-clarkd-wallet-is-ready

    address=$(curl -s http://localhost:7070/v1/admin/wallet/address | jq .address -r)

    echo "Funding clarkd wallet"

    nigiri faucet "$address" 10

# Stop clarkd.
clarkd-kill:
    docker compose -f $CLARKD_COMPOSE_FILE down

_wait-until-clarkd-is-ready:
    #!/usr/bin/env bash

    echo "Waiting for clarkd to be ready..."

    for (( i=0; i<30; i+=1 )); do
      if docker logs clarkd 2>&1 | grep -q "started listening at"; then
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
      res=$(curl -s http://localhost:7070/v1/admin/wallet/status)

      if echo "$res" | jq -e '.initialized == true and .unlocked == true and .synced == true' > /dev/null; then
        echo "clarkd wallet is ready!"
        exit 0
      fi
      sleep 1
    done

    echo "clarkd wallet was not ready in time"

    exit 1
