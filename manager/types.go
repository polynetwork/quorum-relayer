package manager

import (
	"fmt"
	"math/big"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/polynetwork/poly/common"
)

var (
	quorumGasLimit   uint64 = 210000
	quorumTxGasPrice        = big.NewInt(0)
	quorumTxValue           = big.NewInt(0)
)

type CrossTransfer struct {
	txIndex string
	txId    []byte
	value   []byte
	toChain uint32
	height  uint64
}

func (t *CrossTransfer) Serialization(sink *common.ZeroCopySink) {
	sink.WriteString(t.txIndex)
	sink.WriteVarBytes(t.txId)
	sink.WriteVarBytes(t.value)
	sink.WriteUint32(t.toChain)
	sink.WriteUint64(t.height)
}

func (t *CrossTransfer) Deserialization(source *common.ZeroCopySource) error {
	txIndex, eof := source.NextString()
	if eof {
		return fmt.Errorf("Waiting deserialize txIndex error")
	}
	txId, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("Waiting deserialize txId error")
	}
	value, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("Waiting deserialize value error")
	}
	toChain, eof := source.NextUint32()
	if eof {
		return fmt.Errorf("Waiting deserialize toChain error")
	}
	height, eof := source.NextUint64()
	if eof {
		return fmt.Errorf("Waiting deserialize height error")
	}
	t.txIndex = txIndex
	t.txId = txId
	t.value = value
	t.toChain = toChain
	t.height = height
	return nil
}

type QuorumTxInfo struct {
	txData       []byte
	gasLimit     uint64
	gasPrice     *big.Int
	contractAddr ethcommon.Address
	polyTxHash   string
}
