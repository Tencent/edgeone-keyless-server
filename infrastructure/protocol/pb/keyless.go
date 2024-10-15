package keyless

//go:generate trpc create -p keyless_server.proto -o ../keyless --rpconly --protocol=http --alias --mock=false --nogomod=true --validate=true

//go:generate mockgen -source=../keyless/keyless_server.trpc.go -destination=../keyless/mock/keyless_server_mock.go -package=keyless
