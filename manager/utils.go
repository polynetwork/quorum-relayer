package manager

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"

	sccm "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ontio/ontology-crypto/keypair"
	ontsig "github.com/ontio/ontology-crypto/signature"
	polycm "github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	polysig "github.com/polynetwork/poly/core/signature"
	polytyps "github.com/polynetwork/poly/core/types"
	crosscm "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/polynetwork/poly/native/service/header_sync/ont"
	hpl "github.com/polynetwork/poly/native/service/header_sync/quorum"
	"github.com/polynetwork/quorum-relayer/config"
	"github.com/polynetwork/quorum-relayer/go_abi/eccm_abi"
	"github.com/polynetwork/quorum-relayer/log"
	pcm "github.com/polynetwork/quorum-relayer/utils/common"
)

func VerifySig(hash sccm.Hash, multiSigData []byte, keepers []sccm.Address, m int) error {
	sigs, err := RawMultiSigsToList(multiSigData)
	if err != nil {
		return err
	}

	signers, err := RecoverSignersFromMultiSigs(hash, sigs)
	if err != nil {
		return err
	}

	if containsMAddress(signers, keepers, m) {
		return nil
	} else {
		return fmt.Errorf("signers not enough")
	}
}

func RawMultiSigsToList(sigData []byte) ([][]byte, error) {
	if len(sigData)%65 != 0 {
		return nil, fmt.Errorf("invalid sig data length")
	}

	sigCount := len(sigData) / 65
	if sigCount == 0 {
		return nil, fmt.Errorf("sig count should > 0")
	}

	sigs := make([][]byte, sigCount)
	for i := 0; i < sigCount; i++ {
		start := i * 65
		end := (i + 1) * 65
		raw := sigData[start:end]
		sig := make([]byte, 65)
		copy(sig[:], raw[:])
		sigs[i] = sig
	}

	return sigs, nil
}

func RecoverSignersFromMultiSigs(hash sccm.Hash, sigs [][]byte) ([]sccm.Address, error) {
	signers := make([]sccm.Address, len(sigs))
	for i := 0; i < len(sigs); i++ {
		sig := sigs[i]
		enc, err := crypto.Ecrecover(hash[:], sig)
		if err != nil {
			return nil, err
		}
		signer := sccm.BytesToAddress(enc)

		//temp, _ := polycm.AddressParseFromBytes(enc)
		fmt.Println("keeper", signer.Hex()) //temp.ToBase58())

		signers[i] = signer
	}

	return signers, nil
}

func DeserializeKeepers(raw []byte) []polycm.Address {
	source := polycm.NewZeroCopySource(raw)
	keeperLen, _ := source.NextUint64()
	keepers := make([]polycm.Address, keeperLen)

	for i := 0; i < int(keeperLen); i++ {
		keeperBytes, _ := source.NextVarBytes()
		addr := polycm.AddressFromVmCode(keeperBytes)
		keepers[i] = addr
	}
	return keepers
}

func ConvertAddr(base58Addr string) sccm.Address {
	addr, _ := polycm.AddressFromBase58(base58Addr)
	return sccm.BytesToAddress(addr[:])
}

func containsMAddress(signers, contains []sccm.Address, m int) bool {
	in := func(addr sccm.Address) bool {
		for _, signer := range signers {
			if bytes.Equal(signer.Bytes(), addr.Bytes()) {
				return true
			}
		}
		return false
	}

	count := 0
	for _, keeper := range contains {
		if in(keeper) {
			count += 1
		}
	}

	return count >= m
}

func VerifyPolyHeader(hdr *polytyps.Header, peers *ont.ConsensusPeers) error {
	if len(hdr.Bookkeepers)*3 < len(peers.PeerMap)*2 {
		return fmt.Errorf("header Bookkeepers num %d must more than 2/3 consensus node num %d",
			len(hdr.Bookkeepers), len(peers.PeerMap))
	}
	for i, bookkeeper := range hdr.Bookkeepers {
		pubkey := vconfig.PubkeyID(bookkeeper)
		_, present := peers.PeerMap[pubkey]
		if !present {
			return fmt.Errorf("No.%d pubkey is invalid: %s", i, pubkey)
		}
	}
	hash := hdr.Hash()
	if err := polysig.VerifyMultiSignature(
		hash[:],
		hdr.Bookkeepers,
		len(hdr.Bookkeepers),
		hdr.SigData,
	); err != nil {
		return fmt.Errorf("verify sig failed: %v", err)
	}

	return nil
}

type GenesisInitEvent struct {
	Height    uint32 `json:"height"`
	RawHeader []byte `json:"raw_header"`
}

type BookKeepersChangedEvent struct {
	RawPeers []byte `json:"raw_peers"`
}

func assembleHeaderSigs(header *polytyps.Header) []byte {
	sigs := make([]byte, 0)
	for _, sig := range header.SigData {
		temp := make([]byte, len(sig))
		copy(temp, sig)
		compatible, _ := ontsig.ConvertToEthCompatible(temp)
		sigs = append(sigs, compatible...)
	}
	return sigs
}

func dissembleHeaderSigs(raw []byte) ([][]byte, error) {
	if len(raw)%65 != 0 {
		return nil, fmt.Errorf("sig lenght invalid")
	}

	length := len(raw) / 65
	sigs := make([][]byte, length)
	for i := 0; i < length; i++ {
		start := i * 65
		end := (i + 1) * 65
		sigData := make([]byte, 0)
		copy(sigData, raw[start:end])
		sigs[i] = sigData
	}

	return sigs, nil
}

// assemblePubKeyList collect bookkeepers within vbft block info, sort and assemble keepers into a byte slice.
func assemblePubKeyList(blkInfo *vconfig.VbftBlockInfo) (*polycm.ZeroCopySink, []byte) {
	var bookkeepers []keypair.PublicKey
	for _, peer := range blkInfo.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		bookkeepers = append(bookkeepers, key)
	}

	bookkeepers = keypair.SortPublicKeys(bookkeepers)
	pubKeyList := make([]byte, 0)
	sink := polycm.NewZeroCopySink(nil)
	sink.WriteUint64(uint64(len(bookkeepers)))
	for _, key := range bookkeepers {
		raw := pcm.GetNoCompressKey(key)
		pubKeyList = append(pubKeyList, raw...)
		sink.WriteVarBytes(crypto.Keccak256(pcm.GetEthNoCompressKey(key)[1:])[12:])
	}
	return sink, pubKeyList
}

func serializeCrossTransfer(
	evt *eccm_abi.EthCrossChainManagerCrossChainEvent,
	height uint64,
) (*CrossTransfer, *polycm.ZeroCopySink) {
	index := big.NewInt(0)
	index.SetBytes(evt.TxId)

	crossTx := &CrossTransfer{
		txIndex: pcm.EncodeBigInt(index),
		txId:    evt.Raw.TxHash.Bytes(),
		toChain: uint32(evt.ToChainId),
		value:   evt.Rawdata,
		height:  height,
	}
	sink := polycm.NewZeroCopySink(nil)
	crossTx.Serialization(sink)
	return crossTx, sink
}

func deserializeCrossTransfer(retry []byte) (*CrossTransfer, error) {
	crossTx := new(CrossTransfer)
	source := polycm.NewZeroCopySource(retry)
	if err := crossTx.Deserialization(source); err != nil {
		return nil, err
	} else {
		return crossTx, nil
	}
}

// convert poly address to quorum address
func addrConvertUp(addr polycm.Address) sccm.Address {
	return sccm.HexToAddress(addr.ToHexString())
}

// convert quorum address to poly address
func addrConvertDown(addr sccm.Address) (polycm.Address, error) {
	return polycm.AddressFromHexString(addr.Hex())
}

func txIdHex(txID []byte) string {
	return sccm.BytesToHash(txID).Hex()
}

func recoverMakeTxParams(data []byte) *crosscm.MakeTxParam {
	param := &crosscm.MakeTxParam{}
	_ = param.Deserialization(polycm.NewZeroCopySource(data))
	return param
}

func uint64ToBig(n uint64) *big.Int {
	return new(big.Int).SetUint64(n)
}

func uint64ToHex(n uint64) string {
	bn := uint64ToBig(n)
	return hexutil.EncodeBig(bn)
}

func bytesToUint64(bz []byte) uint64 {
	buf := make([]byte, 8)
	copy(buf, bz)
	return binary.LittleEndian.Uint64(buf)
}

func getMappingKey(txIndex string) ([]byte, error) {
	return mappingKeyAt(txIndex, "01")
}

func mappingKeyAt(position1 string, position2 string) ([]byte, error) {
	p1, err := hex.DecodeString(position1)
	if err != nil {
		return nil, err
	}
	p2, err := hex.DecodeString(position2)
	if err != nil {
		return nil, err
	}

	key := crypto.Keccak256(leftPadBytes(p1, 32), leftPadBytes(p2, 32))
	return key, nil
}

func leftPadBytes(slice []byte, l int) []byte {
	if l <= len(slice) {
		return slice
	}
	padded := make([]byte, l)
	copy(padded[l-len(slice):], slice)
	return padded
}

func sortAddrList(list []sccm.Address) {
	sort.Slice(list, func(i, j int) bool {
		return list[i].Hex() < list[j].Hex()
	})
}

func valset2Bytes(vals []sccm.Address) []byte {
	vs := hpl.QuorumValSet(vals)
	sink := polycm.NewZeroCopySink(nil)
	vs.Serialize(sink)
	return sink.Bytes()
}

func bytes2Valset(raw []byte) ([]sccm.Address, error) {
	source := polycm.NewZeroCopySource(raw)
	vs := new(hpl.QuorumValSet)
	if err := vs.Deserialize(source); err != nil {
		return nil, err
	}
	return *vs, nil
}

func convertHashBytes(raw []byte) [32]byte {
	data := [32]byte{}
	copy(data[:], raw[:32])
	return data
}

func debug(format string, args ...interface{}) {
	if config.Debug {
		log.Debugf(format, args...)
	}
}
