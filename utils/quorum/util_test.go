package quorum

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
)

func TestGetNodeHeight(t *testing.T) {
	height, err := GetNodeHeight()
	assert.NoError(t, err)

	t.Logf("current height %d", height)
}

func TestGetNodeHeader(t *testing.T) {
	enc, err := GetNodeHeader(9143)
	assert.NoError(t, err)

	header := new(types.Header)
	err = json.Unmarshal(enc, header)
	assert.NoError(t, err)

	t.Logf("header %v", header)
	t.Logf("block hash %s", header.Hash().Hex())
}

// test data from validator reward
func TestGetProof(t *testing.T) {
	contractAddr := "0x0000000000000000000000000000000000000105"
	blkHash := "0xdc18641ce391557171ec4b02357a19a2f3d2170b84540087d1fd0895eee03184"
	blockHeight := "latest"
	enc, err := GetProof(contractAddr, blkHash, blockHeight)
	assert.NoError(t, err)

	t.Logf("raw proof %s", hexutil.Encode(enc))

	rsp := new(quorumProof)
	err = json.Unmarshal(enc, rsp)
	assert.NoError(t, err)

	t.Logf("proof response %v", rsp)
}
