package poly

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyMultiSigs(t *testing.T) {
	t.Log("one of signers should be ", ConvertAddr("AaodCegA3EWhwd5hRdcKASGnJCPd3RJ3A5").Hex())

	hashData := "0xe1ce0ac357408144ab861ecbf21580c761515dddaaf203781a44b123ce8e7534"
	sigData := "0x54206acfbc4ef1abac8f1cf4948b535725a189b4bd2751a8b801a72c87892e512bd98897015e2d45d11f722811bacad69a3ebac8a6c183ec0c539f540763b784002378260f644b343ea3770f58839fa38d47237eb1ebb3fb6d9e598a7d5905f8142af209c4b4f5926af69016965c4a964db2a56b345b11f5335228e40841eaf0e801f1ef310d8e16b71245750b239118385723a74c1b1d2d37531545d3382d0ae2a15123b1fd6ffefe0a18be2f14b49e1570b4b18bb246a471629a89bef3472095da01"
	keeperData := "0x040000000000000014a42a4e85034d5bebc225743da400cc4c0e43727a145d60f39ab5bec41fa712562a5c098d8a128cd40614da9cdffbfccab4181efc77831dc8ce7c442a7c7f14b98d72dc7743ede561f225e1bf258f49aea8f786"

	enc, err := hexutil.Decode(hashData)
	assert.NoError(t, err)
	hash := common.BytesToHash(enc)

	rawSigs, err := hexutil.Decode(sigData)
	assert.NoError(t, err)

	rawkeepers, err := hexutil.Decode(keeperData)
	assert.NoError(t, err)

	keepers := DeserializeKeepers(rawkeepers)

	err = VerifySig(hash, rawSigs, keepers, 1)
	assert.NoError(t, err)
}
