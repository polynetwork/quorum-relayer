## Quorum-relayer

Quorum Relayer is an important character of Poly cross-chain interactive protocol which is responsible for relaying cross-chain transaction from and to Quorum.

## Build From Source

### Prerequisites

- [Golang](https://golang.org/doc/install) version 1.15 or later

### Build

```shell
git clone https://github.com/polynetwork/quorum-relayer.git
cd quorum-relayer
go build -o relayer main.go
```

### Configuration
configuration as follow:
```
{
  "MultiChainConfig":{
    "RestURL":"http://poly_ip:20336", // address of Poly
    "EntranceContractAddress":"0300000000000000000000000000000000000000", // CrossChainManagerContractAddress on Poly. No need to change
    "WalletFile":"./wallet.dat", // your poly wallet file
    "WalletPwd":"pwd" //password
  },
  "QuorumConfig":{
    "SideChainId": 101, // palette side chain ID in poly network
    "RestURL":"http://palette:port", // your palette node rpc url 
    "ECCMContractAddress":"ethereum_cross_chain_contract", 
    "ECCDContractAddress":"ethereum_cross_chain_data_contract",
    "KeyStorePath": "./keystore", // path to store your ethereum wallet
    "KeyStorePwdSet": { // password to protect your ethereum wallet
      "0xd12e...4d": "pwd1", // password for address "0xd12e...4d"
      "0xabb4...53": "pwd2" // password for address "0xabb4...53"
    },
    "BlockConfig": 6, // blocks to confirm a tx
    "HeadersPerBatch": 500 // number of poly headers commited to ECCM in one transaction at most
  },
  "BoltDbPath": "boltdb", // DB path
  "RoutineNum": 64,
  "TargetContracts": [
    {
      "0xCeE9****744": { // your lock proxy address
        "inbound": [101],  // src/dst side chain id 
        "outbound": [101], // dst/src side chain id
      }
    }
  ]
}
```

## Run Relayer

There are serveral steps before running relayer:
* create an wallet file of polynetwork.
* register side chain on poly.
* approve side chain on poly.
* deploy eccd contract on quorum chain.
* deploy eccm contract on quorum chain.
* deploy ccmp contract on quorum chain.
* deploy lock proxy contract on quorum chain.
* bind proxy to destination proxy.
* bind asset to destination asset.

Now, you can start relayer as follow: 

```shell
./relayer --help

./relayer --cliconfig=./config.json 
```

It will generate logs under `./Log` and check relayer status by view log file.

