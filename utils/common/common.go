package common

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/sm2"
	"github.com/polynetwork/poly/common"
)

func EncodeBigInt(b *big.Int) string {
	if b.Uint64() == 0 {
		return "00"
	}
	return hex.EncodeToString(b.Bytes())
}

// ParseAuditPath
func ParseAuditPath(path []byte) ([]byte, []byte, [][32]byte, error) {
	source := common.NewZeroCopySource(path)

	value, eof := source.NextVarBytes()
	if eof {
		return nil, nil, nil, nil
	}
	size := int((source.Size() - source.Pos()) / common.UINT256_SIZE)
	pos := make([]byte, 0)
	hashs := make([][32]byte, 0)
	for i := 0; i < size; i++ {
		f, eof := source.NextByte()
		if eof {
			return nil, nil, nil, nil
		}
		pos = append(pos, f)

		v, eof := source.NextHash()
		if eof {
			return nil, nil, nil, nil
		}
		var onehash [32]byte
		copy(onehash[:], (v.ToArray())[0:32])
		hashs = append(hashs, onehash)
	}

	return value, pos, hashs, nil
}

func GetNoCompressKey(key keypair.PublicKey) []byte {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			// Take P-256 as a special case
			if t.Params().Name == elliptic.P256().Params().Name {
				return ec.EncodePublicKey(t.PublicKey, false)
			}
			buf.WriteByte(byte(0x12))
		case ec.SM2:
			buf.WriteByte(byte(0x13))
		}
		label, err := GetCurveLabel(t.Curve.Params().Name)
		if err != nil {
			panic(err)
		}
		buf.WriteByte(label)
		buf.Write(ec.EncodePublicKey(t.PublicKey, false))
	case ed25519.PublicKey:
		panic("err")
	default:
		panic("err")
	}
	return buf.Bytes()
}

// todo:
//func ParseCompressKey(raw []byte) keypair.PublicKey {
//
//}

func GetCurveLabel(name string) (byte, error) {
	switch strings.ToUpper(name) {
	case strings.ToUpper(elliptic.P224().Params().Name):
		return 1, nil
	case strings.ToUpper(elliptic.P256().Params().Name):
		return 2, nil
	case strings.ToUpper(elliptic.P384().Params().Name):
		return 3, nil
	case strings.ToUpper(elliptic.P521().Params().Name):
		return 4, nil
	case strings.ToUpper(sm2.SM2P256V1().Params().Name):
		return 20, nil
	case strings.ToUpper(btcec.S256().Name):
		return 5, nil
	default:
		panic("err")
	}
}

// todo(fuk): set fixed value
func GetExplorerUrl(chainId uint64) string {
	return "https://etherscan.io/tx/"

	switch chainId {
	case params.MainnetChainConfig.ChainID.Uint64():
		return "https://etherscan.io/tx/"
	default:
		return "no url"
	}
}

func GetEthNoCompressKey(key keypair.PublicKey) []byte {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		return crypto.FromECDSAPub(t.PublicKey)
	default:
		panic("err")
	}
	return buf.Bytes()
}
