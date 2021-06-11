module github.com/polynetwork/quorum-relayer

go 1.15

require (
	github.com/boltdb/bolt v1.3.1
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/ethereum/go-ethereum v1.9.15
	github.com/golang/mock v1.3.1 // indirect
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/ontio/ontology-crypto v1.0.9
	github.com/polynetwork/poly v0.0.1
	github.com/polynetwork/poly-go-sdk v0.0.0-20200730112529-d9c0c7ddf3d8
	github.com/polynetwork/poly-io-test v0.0.0-20200819093740-8cf514b07750 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli v1.22.4
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
)

replace github.com/polynetwork/poly v0.0.1 => github.com/zouxyan/poly v0.0.0-20210114022211-0478125d30b3
