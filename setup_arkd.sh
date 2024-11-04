#!/usr/bin/env bash

docker compose -f docker-compose.clark.regtest.yml up

seed=$(curl http://localhost:7070/v1/admin/wallet/seed | jq .seed -r)

curl --data-binary '{"seed": "$seed", "password": "password"}' -H "Content-Type: application/json" http://localhost:7070/v1/admin/wallet/create

sleep 1

curl --data-binary '{"password" : "password"}' -H "Content-Type: application/json" http://localhost:7070/v1/admin/wallet/unlock

sleep 1

curl http://localhost:7070/v1/info | jq .


sleep 1

curl http://localhost:7070/v1/admin/wallet/status

address=$(curl http://localhost:7070/v1/admin/wallet/address | jq .address -r)

nigiri faucet "$address" 10
