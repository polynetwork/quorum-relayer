/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */

package manager

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	sccm "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	sccli "github.com/ethereum/go-ethereum/ethclient"
	sdk "github.com/polynetwork/poly-go-sdk"
	polysdkcm "github.com/polynetwork/poly-go-sdk/common"
	polycm "github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	polytypes "github.com/polynetwork/poly/core/types"
	crosscm "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/polynetwork/quorum-relayer/config"
	"github.com/polynetwork/quorum-relayer/db"
	"github.com/polynetwork/quorum-relayer/go_abi/eccd_abi"
	"github.com/polynetwork/quorum-relayer/go_abi/eccm_abi"
	"github.com/polynetwork/quorum-relayer/log"
	"github.com/polynetwork/quorum-relayer/utils/common"
	"github.com/polynetwork/quorum-relayer/utils/keystore"
	"github.com/polynetwork/quorum-relayer/utils/nonce"
)

const (
	ChanLen = 64
)

type PolyManager struct {
	config *config.ServiceConfig
	db     *db.BoltDB

	polySdk   *sdk.PolySdk
	quorumCli *sccli.Client
	senders   []*QuorumSender
	eccd      *eccd_abi.EthCrossChainData // quorum eccd contract

	currentHeight uint32

	exitChan chan int
}

// 从poly到quorum
func NewPolyManager(
	srvCfg *config.ServiceConfig,
	polyForceStartBlockHeight uint32,
	polySDK *sdk.PolySdk,
	quorumSDK *sccli.Client,
	boltDB *db.BoltDB,
) (*PolyManager, error) {

	reader := strings.NewReader(eccm_abi.EthCrossChainManagerABI)
	contractABI, err := abi.JSON(reader)
	if err != nil {
		return nil, err
	}

	chainId, err := quorumSDK.ChainID(context.Background())
	if err != nil {
		return nil, err
	}

	ks, accArr, err := srvCfg.ImportQuorumAccount(chainId)
	if err != nil {
		return nil, err
	}

	mgr := &PolyManager{
		exitChan:      make(chan int),
		config:        srvCfg,
		polySdk:       polySDK,
		currentHeight: polyForceStartBlockHeight,
		db:            boltDB,
		quorumCli:     quorumSDK,
	}

	senders := make([]*QuorumSender, len(accArr))
	nonceMgr := nonce.NewNonceManager(quorumSDK)
	for i, v := range senders {
		eccd, err := eccd_abi.NewEthCrossChainData(mgr.eccdContract(), quorumSDK)
		if err != nil {
			return nil, err
		}

		v = &QuorumSender{
			acc:          accArr[i],
			client:       quorumSDK,
			keyStore:     ks,
			config:       srvCfg,
			polySdk:      polySDK,
			contractAbi:  &contractABI,
			nonceManager: nonceMgr,
			cmap:         make(map[string]chan *QuorumTxInfo),
			eccd:         eccd,
		}
		senders[i] = v
	}
	mgr.senders = senders

	mgr.init()

	return mgr, nil
}

func (m *PolyManager) init() {
	eccd, err := eccd_abi.NewEthCrossChainData(m.eccdContract(), m.quorumCli)
	if err != nil {
		panic(fmt.Sprintf("PolyManager init - generate eccd contract err: %s", err))
	}
	m.eccd = eccd

	// current height settle as poly force start height
	if m.currentHeight > 0 {
		log.Infof("PolyManager init - start height from flag: %d", m.currentHeight)
		return
	}

	m.currentHeight = m.db.GetPolyHeight()
	latestHeight := m.findLastEpochHeight()
	if latestHeight > m.currentHeight {
		m.currentHeight = latestHeight
		log.Infof("PolyManager init - latest height from ECCM: %d", m.currentHeight)
	} else {
		log.Infof("PolyManager init - latest height from DB: %d", m.currentHeight)
	}
}

func (m *PolyManager) MonitorChain() {
	ticker := time.NewTicker(config.ONT_MONITOR_INTERVAL)

	for {
		select {
		case <-ticker.C:
			latestHeight, err := m.polySdk.GetCurrentBlockHeight()
			if err != nil {
				log.Errorf("PolyManager MonitorChain - get poly chain block height error: %s", err)
				continue
			}

			latestHeight -= 1
			workHeightEnd := latestHeight - config.ONT_USEFUL_BLOCK_NUM
			if workHeightEnd < m.currentHeight {
				log.Infof("PolyManager MonitorChain - poly chain current height: %d, loop end height %d", m.currentHeight, workHeightEnd)
				continue
			}
			// log.Infof("PolyManager MonitorChain - poly chain current height: %d", latestHeight)

			for ; m.currentHeight <= workHeightEnd; m.currentHeight++ {
				log.Infof("PolyManager MonitorChain - poly chain current height: %d, loop end height %d", m.currentHeight, workHeightEnd)
				if !m.handleDepositEvents(m.currentHeight) {
					break
				}
			}

			if err := m.db.UpdatePolyHeight(m.currentHeight - 1); err != nil {
				log.Errorf("PolyManager MonitorChain - failed to save height of poly: %v", err)
			}

		case <-m.exitChan:
			return
		}
	}
}

// findLastEpochHeight get current pltEpoch start height which record in `crossChainManager`
// contract located on quorum chain.
func (m *PolyManager) findLastEpochHeight() uint32 {
	if height, err := m.eccd.GetCurEpochStartHeight(nil); err != nil {
		log.Errorf("PolyManager findLastEpochHeight - GetLatestHeight failed: %s", err.Error())
		return 0
	} else {
		return height
	}
}

func (m *PolyManager) handleDepositEvents(height uint32) bool {
	lastEpoch := m.findLastEpochHeight()
	validStateHeight := height + 1
	hdr, err := m.polySdk.GetHeaderByHeight(validStateHeight)
	if err != nil {
		log.Errorf("PolyManager handleDepositEvents - GetNodeHeader on height :%d failed", height)
		return false
	}

	isCurr := lastEpoch < validStateHeight
	isEpoch, pubKeyList, err := m.isEpoch(hdr)
	if err != nil {
		log.Errorf("PolyManager handleDepositEvents - failed to check isEpoch: %v", err)
		return false
	}

	var (
		anchor *polytypes.Header
		hp     string
	)
	if !isCurr {
		anchor, _ = m.polySdk.GetHeaderByHeight(lastEpoch + 1)
		proof, _ := m.polySdk.GetMerkleProof(validStateHeight, lastEpoch+1)
		hp = proof.AuditPath
	} else if isEpoch {
		anchor, _ = m.polySdk.GetHeaderByHeight(validStateHeight + 1)
		proof, _ := m.polySdk.GetMerkleProof(validStateHeight, validStateHeight+1)
		hp = proof.AuditPath
	}

	events, err := m.polySdk.GetSmartContractEventByBlock(height)
	for err != nil {
		log.Errorf("PolyManager handleDepositEvents - get block event at height:%d error: %s", height, err.Error())
		return false
	}

	cnt := 0
	for _, event := range events {
		for _, notify := range event.Notify {
			if !m.checkNotifyAddr(notify.ContractAddress) {
				//debug("PolyManager handleDepositEvents - notify contract address mismatch, need %s, actual %s",
				//	m.entranceContract().Hex(), notify.ContractAddress)
				continue
			}

			proof := m.getProofWithNotify(height, notify)
			if proof == nil {
				debug("PolyManager handleDepositEvents - getProofWithNotify nil")
				continue
			}

			auditPath, _ := hex.DecodeString(proof.AuditPath)
			value, _, _, _ := common.ParseAuditPath(auditPath)
			merkle := &crosscm.ToMerkleValue{}
			if err := merkle.Deserialization(polycm.NewZeroCopySource(value)); err != nil {
				debug("PolyManager handleDepositEvents - failed to deserialize MakeTxParam (value: %x, err: %v)",
					value, err)
				continue
			}

			addr := sccm.BytesToAddress(merkle.MakeTxParam.ToContractAddress)
			if !m.config.TargetContracts.CheckContract(addr, "inbound", merkle.FromChainID) {
				debug("PolyManager handleDepositEvents - merkle param's fromChainID mismatch %d", merkle.FromChainID)
				continue
			}

			cnt++
			sender := m.selectSender()
			sender.commitDepositEventsWithHeader(hdr, merkle, hp, anchor, event.TxHash, auditPath)

			log.Infof("PolyManager sender %s is handling poly tx ( hash: %s, height: %d )",
				sender.acc.Address.String(), event.TxHash, height)
		}
	}

	if cnt == 0 && isEpoch && isCurr {
		sender := m.selectSender()
		return sender.commitHeader(hdr, pubKeyList)
	}

	return true
}

// bookkeeper变更返回true
func (m *PolyManager) isEpoch(hdr *polytypes.Header) (bool, []byte, error) {
	// get keepers valset from block info
	blkInfo := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(hdr.ConsensusPayload, blkInfo); err != nil {
		return false, nil, fmt.Errorf("PolyManager commitHeader - unmarshal blockInfo error: %s", err)
	}
	if hdr.NextBookkeeper == polycm.ADDRESS_EMPTY || blkInfo.NewChainConfig == nil {
		return false, nil, nil
	}

	// get raw keepers' byte slice
	rawKeepers, err := m.eccd.GetCurEpochConPubKeyBytes(nil)
	if err != nil {
		return false, nil, fmt.Errorf("PolyManager failed to get current pltEpoch keepers: %v", err)
	}

	// compare and return
	sink, pubKeyList := assemblePubKeyList(blkInfo)
	if bytes.Equal(rawKeepers, sink.Bytes()) {
		return false, nil, nil
	}
	return true, pubKeyList, nil
}

func (m *PolyManager) getProofWithNotify(height uint32, notify *polysdkcm.NotifyEventInfo) *polysdkcm.MerkleProof {
	states := notify.States.([]interface{})
	if len(states) < 6 {
		debug("PolyManager handleDepositEvents - notify states not enough: %d", len(states))
		return nil
	}

	method, _ := states[0].(string)
	sideChainId := uint64(states[2].(float64))
	proofKey := states[5].(string)

	if method != "makeProof" {
		debug("PolyManager handleDepositEvents - method invalid, need `makeProof`, actual %d", method)
		return nil
	}

	if sideChainId != m.sideChainID() {
		debug("PolyManager handleDepositEvents - side chain id mismatch, need %d, actual %d",
			m.sideChainID(), sideChainId)
		return nil
	}

	proof, err := m.polySdk.GetCrossStatesProof(height, proofKey)
	if err != nil {
		log.Errorf("PolyManager handleDepositEvents - failed to get proof for key %s: %v", proofKey, err)
		return nil
	}

	return proof
}

func (m *PolyManager) selectSender() *QuorumSender {
	if len(m.senders) == 1 {
		return m.senders[0]
	}

	idx := rand.Intn(len(m.senders))
	return m.senders[idx]
}

func (m *PolyManager) Stop() {
	m.exitChan <- 1
	close(m.exitChan)
	log.Infof("poly chain manager exit.")
}

type QuorumSender struct {
	acc          accounts.Account
	keyStore     *keystore.QuorumKeyStore
	cmap         map[string]chan *QuorumTxInfo
	nonceManager *nonce.NonceManager
	client       *sccli.Client
	polySdk      *sdk.PolySdk
	config       *config.ServiceConfig
	contractAbi  *abi.ABI
	eccd         *eccd_abi.EthCrossChainData
}

// commitDepositEventsWithHeader
func (s *QuorumSender) commitDepositEventsWithHeader(
	header *polytypes.Header,
	param *crosscm.ToMerkleValue,
	headerProof string,
	anchorHeader *polytypes.Header,
	polyTxHash string,
	auditPath []byte,
) bool {

	var sigs []byte
	if anchorHeader != nil && headerProof != "" {
		sigs = assembleHeaderSigs(anchorHeader)
		log.Infof("PolyManager - assemble anchor header sigs")
	} else {
		sigs = assembleHeaderSigs(header)
		log.Infof("PolyManager - assemble header sigs")
	}

	fromTx := convertHashBytes(param.TxHash)
	if ok, _ := s.eccd.CheckIfFromChainTxExist(nil, param.FromChainID, fromTx); ok {
		log.Debugf("PolyManager - already relayed to eth: ( from_chain_id: %d, from_txhash: %x,  param.Txhash: %x)",
			param.FromChainID, param.TxHash, param.MakeTxParam.TxHash)
		return true
	}

	var (
		rawAnchor   []byte
		rawProof, _ = hex.DecodeString(headerProof)
	)
	if anchorHeader != nil {
		rawAnchor = anchorHeader.GetMessage()
	}
	headerData := header.GetMessage()
	txData, err := s.contractAbi.Pack(
		"verifyHeaderAndExecuteTx",
		auditPath,
		headerData,
		rawProof,
		rawAnchor,
		sigs,
	)

	hash := header.Hash()
	debug("PolyManager - commitDepositEventsWithHeader debug:"+
		" hash %s, auditPath %s, headerData %s, rawProof %s, rawAnchor %s, sigs %s",
		hash.ToHexString(),
		hexutil.Encode(auditPath),
		hexutil.Encode(headerData),
		hexutil.Encode(rawProof),
		hexutil.Encode(rawAnchor),
		hexutil.Encode(sigs),
	)

	if err != nil {
		log.Errorf("PolyManager - commitDepositEventsWithHeader - err:" + err.Error())
		return false
	}

	// 并发发交易
	k := s.getRouter()
	c, ok := s.cmap[k]
	if !ok {
		c = make(chan *QuorumTxInfo, ChanLen)
		s.cmap[k] = c
		go func() {
			for v := range c {
				if err = s.sendTxToQuorum(v.contractAddr, v.polyTxHash, v.txData); err != nil {
					log.Errorf("PolyManager - failed to send tx to ethereum: error: %v, txData: %s",
						err, hex.EncodeToString(v.txData))
				}
			}
		}()
	}

	c <- &QuorumTxInfo{
		txData:       txData,
		contractAddr: s.eccmContract(),
		gasPrice:     quorumTxGasPrice,
		gasLimit:     quorumGasLimit,
		polyTxHash:   polyTxHash,
	}
	return true
}

// 往quorum管理合约提交changeBookKeeper tx
func (s *QuorumSender) commitHeader(header *polytypes.Header, pubkList []byte) bool {
	headerDat := header.GetMessage()
	sigs := assembleHeaderSigs(header)
	txDat, err := s.contractAbi.Pack("changeBookKeeper", headerDat, pubkList, sigs)
	if err != nil {
		log.Errorf("PolyManager commitHeader - err:" + err.Error())
		return false
	}

	contractAddr := s.eccmContract()
	polyTxHash := fmt.Sprintf("header: %d", header.Height)
	if err := s.sendTxToQuorum(contractAddr, polyTxHash, txDat); err != nil {
		log.Errorf("PolyManager commitHeader - send transaction error:%s\n", err.Error())
		return false
	}

	return true
}

func (s *QuorumSender) sendTxToQuorum(
	contractAddr sccm.Address,
	polyTxHash string,
	txData []byte,
) (err error) {

	curNonce := s.nonceManager.UseNonce(s.acc.Address)
	tx := types.NewTransaction(
		curNonce,
		contractAddr,
		quorumTxValue,
		quorumGasLimit,
		quorumTxGasPrice,
		txData,
	)

	defer func() {
		if err != nil {
			s.nonceManager.ReturnNonce(s.acc.Address, curNonce)
		}
	}()

	var signedTx *types.Transaction
	if signedTx, err = s.keyStore.SignTransaction(tx, s.acc); err != nil {
		err = fmt.Errorf("PolyManager commitDepositEventsWithHeader - sign raw tx error and return curNonce %d: %v",
			curNonce, err)
		return
	}

	// sendTransaction to quorum, params should contain an nil bind.PrivateTransaction which definated in "github.com/ethereum/go-ethereum/accounts/abi/bind",
	// we use sendTransaction instead because of that when the PrivateTxArgs is nil, it will callContext with `eth_sendRawTransaction`.
	// if err = s.client.SendTransaction(context.Background(), signedTx, bind.PrivateTxArgs{}); err != nil {
	if err = s.client.SendTransaction(context.Background(), signedTx); err != nil {
		err = fmt.Errorf("PolyManager commitDepositEventsWithHeader - send transaction error and return curNonce %d: %v",
			curNonce, err)
		return
	}

	hash := signedTx.Hash()
	url := common.GetExplorerUrl(s.keyStore.GetChainId()) + hash.String()
	logInf := fmt.Sprintf(" to relay tx to ethereum: (eth_hash: %s, sender: %s, curNonce: %d, "+
		"poly_hash: %s, eth_explorer: %s)", hash.String(), s.acc.Address.Hex(), curNonce, polyTxHash, url)

	if s.waitTransactionConfirm(polyTxHash, hash) {
		log.Infof("PolyManager - successful %s", logInf)
	} else {
		log.Errorf("PolyManager - failed %s", logInf)
	}

	return
}

func (s *QuorumSender) waitTransactionConfirm(polyTxHash string, hash sccm.Hash) bool {
	for {
		time.Sleep(time.Second * 2)

		_, pending, err := s.client.TransactionByHash(context.Background(), hash)
		if err != nil {
			continue
		}

		if pending {
			log.Infof("PolyManager - ( eth_transaction %s, poly_tx %s ) is pending: %v",
				hash.String(), polyTxHash, pending)
			continue
		}

		receipt, err := s.client.TransactionReceipt(context.Background(), hash)
		if err != nil {
			continue
		}

		return receipt.Status == types.ReceiptStatusSuccessful
	}
}

func (s *QuorumSender) getRouter() string {
	return strconv.FormatInt(rand.Int63n(s.config.RoutineNum), 10)
}

func (s *QuorumSender) getExploreUrl(txHash sccm.Hash) string {
	return common.GetExplorerUrl(s.keyStore.GetChainId()) + txHash.String()
}

func (s *QuorumSender) eccmContract() sccm.Address {
	return sccm.HexToAddress(s.config.QuorumConfig.ECCMContractAddress)
}

func (m *PolyManager) eccdContract() sccm.Address {
	return sccm.HexToAddress(m.config.QuorumConfig.ECCDContractAddress)
}

func (m *PolyManager) entranceContract() sccm.Address {
	return sccm.HexToAddress(m.config.PolyConfig.EntranceContractAddress)
}

func (m *PolyManager) sideChainID() uint64 {
	return m.config.QuorumConfig.SideChainId
}

func (m *PolyManager) checkNotifyAddr(addr string) bool {
	b1 := sccm.HexToAddress(addr).Bytes()
	b2 := m.entranceContract().Bytes()
	return bytes.Equal(b1, b2)
}
