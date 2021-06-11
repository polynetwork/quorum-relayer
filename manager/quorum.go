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
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	sccm "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	sctyp "github.com/ethereum/go-ethereum/core/types"
	sccli "github.com/ethereum/go-ethereum/ethclient"
	polysdk "github.com/polynetwork/poly-go-sdk"
	ccm "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	synccm "github.com/polynetwork/poly/native/service/header_sync/common"
	autils "github.com/polynetwork/poly/native/service/utils"
	"github.com/polynetwork/quorum-relayer/config"
	"github.com/polynetwork/quorum-relayer/db"
	"github.com/polynetwork/quorum-relayer/go_abi/eccm_abi"
	"github.com/polynetwork/quorum-relayer/log"
	"github.com/polynetwork/quorum-relayer/utils/quorum"
	"github.com/polynetwork/quorum-relayer/utils/rest"
)

var (
	polyHeaderSyncContract    = autils.HeaderSyncContractAddress.ToHexString()
	polyCrossChainMgrContract = autils.CrossChainManagerContractAddress
)

type pltEpoch struct {
	height uint64
	valset []sccm.Address
	raw    []byte
}

// QuorumManager quorum->poly:
// 1. record quorum height in poly
// 2. fetch quorum header and proof and send to poly chain
// 3. The synchronization process is often batch processing, rather than block-by-block synchronization or submitting
// events, etc., so two slices are required to record the header and crossTx.
// 4. To ensure that each block is not dropped, we need a currentHeight mark stored in the headerSync contract
// of the relay chain to record which block is currently processed.
// 5. A cross chain manager is required to obtain cross-chain events from the solidity contract on the quorum chain
type QuorumManager struct {
	config *config.ServiceConfig
	db     *db.BoltDB

	restClient      *rest.RestClient
	quorumClient    *sccli.Client
	quorumLockProxy *eccm_abi.EthCrossChainManager
	polySdk         *polysdk.PolySdk
	polySigner      *polysdk.Account

	currentSyncHeaderHeight,
	currentDepositHeight,
	forceHeight uint64

	lastEpoch,
	curHeader *pltEpoch

	exitChan chan int
}

func NewQuorumManager(
	cfg *config.ServiceConfig,
	startHeight,
	startForceHeight uint64,
	polySdk *polysdk.PolySdk,
	quorumClient *sccli.Client,
	boltDB *db.BoltDB,
) (*QuorumManager, error) {

	signer, err := cfg.OpenPolyWallet(polySdk)
	if err != nil {
		return nil, err
	}

	if len(cfg.TargetContracts) == 0 {
		return nil, fmt.Errorf("NewETHManager - no target contracts")
	}

	lockAddress := sccm.HexToAddress(cfg.QuorumConfig.ECCMContractAddress)
	lockContract, err := eccm_abi.NewEthCrossChainManager(lockAddress, quorumClient)
	if err != nil {
		log.Errorf("NewQuorumManager - generate instance of cross chain manager err: %s", err.Error())
		return nil, err
	}

	restCli := rest.NewRestClient()
	quorum.Initialize(cfg.QuorumConfig.RestURL, restCli)

	mgr := &QuorumManager{
		config:                  cfg,
		exitChan:                make(chan int),
		currentSyncHeaderHeight: startHeight,
		forceHeight:             startForceHeight,
		restClient:              restCli,
		quorumClient:            quorumClient,
		quorumLockProxy:         lockContract,
		polySdk:                 polySdk,
		polySigner:              signer,
		db:                      boltDB,
	}

	if err := mgr.init(); err != nil {
		log.Errorf("NewQuorumManager - init manager err: %s", err)
		return nil, err
	}

	log.Infof("NewQuorumManager - poly signer address: %s", signer.Address.ToBase58())
	return mgr, nil
}

// init find latest block height on poly chain and valset this value as current height of `quorum manager`.
// when an irreversible error occurs in the cross-chain process, we can start over by some fixed block
// height which is lower than the current height.
func (m *QuorumManager) init() error {
	lastEpoch := m.findLastEpochHeight()
	if lastEpoch == 0 {
		return fmt.Errorf("init - the genesis block has not synced!")
	}
	if !m.fetchLastEpoch(lastEpoch) {
		return fmt.Errorf("init - find the genesis header failded")
	}

	curHeight := m.db.GetQuorumHeight()
	if curHeight == 0 {
		curHeight = lastEpoch
	}
	if m.forceHeight > 0 && m.forceHeight < curHeight {
		curHeight = m.forceHeight
	}

	m.currentSyncHeaderHeight = curHeight
	m.currentDepositHeight = curHeight
	log.Infof("QuorumManager init - start height: %d", curHeight)

	return nil
}

// MonitorChain the `QuorumManager` needs to traverse all of blocks and events on the quorum chain,
// and record the relationship of block height and block content which contains block header and event logs.
// and these data should be synced to `headerSync` and `crossChainManager` contracts located on poly chain.
func (m *QuorumManager) MonitorChain() {
	ticker := time.NewTicker(config.PLT_MONITOR_INTERVAL)
	for {
		select {
		case <-ticker.C:
			height, err := quorum.GetNodeHeight()
			if err != nil {
				log.Infof("QuorumManager MonitorChain - cannot get node height, err: %s", err)
				continue
			}

			for m.currentSyncHeaderHeight < height {
				if m.handleNewBlock(m.currentSyncHeaderHeight) {
					_ = m.db.UpdateQuorumHeight(m.currentSyncHeaderHeight)
					m.currentSyncHeaderHeight++
					log.Infof("QuorumManager MonitorChain - current height %d, quorum height is %d",
						m.currentSyncHeaderHeight, height)
				} else {
					time.Sleep(1 * time.Second)
				}
			}

		case <-m.exitChan:
			return
		}
	}
}

func (m *QuorumManager) MonitorDeposit() {
	ticker := time.NewTicker(config.PLT_MONITOR_INTERVAL)
	for {
		select {
		case <-ticker.C:
			for m.currentDepositHeight < m.currentSyncHeaderHeight {
				_ = m.handleDepositEvents(m.currentDepositHeight)
				m.currentDepositHeight++
			}
		case <-m.exitChan:
			return
		}
	}
}

func (m *QuorumManager) CheckDeposit() {
	ticker := time.NewTicker(config.PLT_MONITOR_INTERVAL)
	for {
		select {
		case <-ticker.C:
			_ = m.checkLockEvents()
		case <-m.exitChan:
			return
		}
	}
}

// findLastEpochHeight get current block height which recorded on `crossChainManager` contract located on poly chain.
func (m *QuorumManager) findLastEpochHeight() uint64 {
	key := m.formatStorageKey(synccm.CONSENSUS_PEER_BLOCK_HEIGHT, nil)
	result, _ := m.polySdk.GetStorage(polyHeaderSyncContract, key)
	return bytesToUint64(result)
}

// handleNewBlock retry if handle block header failed. if handle events failed, just ignore.
func (m *QuorumManager) handleNewBlock(height uint64) bool {
	if m.checkEpochHeight(height) {
		if !m.fetchBlockHeader(height) {
			log.Errorf("QuorumManager handleNewBlock - fetchBlockHeader on height :%d failed", height)
			return false
		}

		if m.isEpoch() && !m.commitHeader() {
			log.Errorf("QuorumManager handleNewBlock - commitHeader on height :%d failed", height)
			return false
		}
	}

	if !m.fetchLockEvents(height) {
		log.Errorf("QuorumManager handleNewBlock - fetchLockEvents on height :%d failed", height)
	}
	return true
}

// fetchBlockHeader get block header from quorum chain, append header
// in cache if it's not exist in poly chain.
func (m *QuorumManager) fetchBlockHeader(height uint64) bool {
	if m.curHeader != nil && m.curHeader.height == height {
		return true
	}

	// get validators of current block
	hdr, err := m.quorumClient.HeaderByNumber(context.Background(), uint64ToBig(height))
	if err != nil {
		log.Errorf("QuorumManager fetchBlockHeader - GetNodeHeader on height :%d failed", height)
		return false
	}

	// compare header
	raw, err := quorum.MarshalJSON(*hdr) //hdr.MarshalJSON()
	if err != nil {
		log.Errorf("QuorumManager fetchBlockHeader - marshal current block header err: %s", err)
		return false
	}
	if m.curHeader != nil && bytes.Equal(raw, m.curHeader.raw) {
		return true
	}

	// get validators
	extra, err := quorum.ExtractIstanbulExtra(hdr)
	if err != nil {
		log.Errorf("QuorumManager fetchBlockHeader - extract istanbul extra err: %s", err)
		return false
	}

	m.curHeader = &pltEpoch{
		height: height,
		raw:    raw,
		valset: extra.Validators,
	}

	return true
}

// get validators of last pltEpoch
func (m *QuorumManager) fetchLastEpoch(height uint64) bool {
	key := m.formatStorageKey(
		synccm.CONSENSUS_PEER,
		nil,
	)
	raw, err := m.polySdk.GetStorage(polyHeaderSyncContract, key)
	if err != nil {
		log.Errorf("QuorumManager fetchLastEpoch - get storage err: %s", err)
		return false
	}

	vals, err := bytes2Valset(raw)
	if err != nil {
		log.Errorf("QuorumManager fetchLastEpoch - deserialize poly valset err: %s", err)
		return false
	}

	m.lastEpoch = &pltEpoch{
		height: height,
		raw:    raw,
		valset: vals,
	}

	return true
}

func (m *QuorumManager) commitHeader() bool {
	tx, err := m.polySdk.Native.Hs.SyncBlockHeader(
		m.sideChainID(),
		m.polySigner.Address,
		[][]byte{m.curHeader.raw},
		m.polySigner,
	)
	if err != nil {
		log.Errorf("QuorumManager commitHeader - sync block header err: %s", err)
		return false
	}

	// waiting for transaction confirmed on poly chain, and the landmark event is that
	// current block height on poly chain is bigger than tx's height.
	var h uint32
	ticker := time.NewTicker(1 * time.Second)
	for range ticker.C {
		if h == 0 {
			h, _ = m.polySdk.GetBlockHeightByTxHash(tx.ToHexString())
		} else {
			curr, _ := m.polySdk.GetCurrentBlockHeight()
			if curr > h {
				m.lastEpoch.height = m.curHeader.height
				m.lastEpoch.raw = m.curHeader.raw
				m.lastEpoch.valset = m.curHeader.valset
				break
			}
		}
	}

	log.Infof("QuorumManager commitHeader - send (quorum transaction %s, quorum header height %d, valset size %d) "+
		"to poly chain and confirmed on poly height %d", tx.ToHexString(), m.curHeader.height, len(m.curHeader.valset), h)

	return true
}

func (m *QuorumManager) isEpoch() bool {
	s1 := m.curHeader.valset
	s2 := m.lastEpoch.valset

	if len(s1) != len(s2) {
		return true
	}

	sortAddrList(s1)
	sortAddrList(s2)

	for i := 0; i < len(s1); i++ {
		if s1[i] != s2[i] {
			return true
		}
	}

	return false
}

// checkEpochHeight return true if height is bigger than last pltEpoch height
func (m *QuorumManager) checkEpochHeight(height uint64) bool {
	if height <= m.lastEpoch.height {
		return false
	}
	return true
}

// fetchLockEvents get cross chain events from lock proxy contract which located on quorum chain.
// filter events which has incorrect contract address or already exist in poly chain, and cache these
// events data in `retry` bucket of blot database.
func (m *QuorumManager) fetchLockEvents(height uint64) bool {
	opt := &bind.FilterOpts{
		Start:   height,
		End:     &height,
		Context: context.Background(),
	}
	iter, err := m.quorumLockProxy.FilterCrossChainEvent(opt, nil)
	if err != nil {
		debug("QuorumManager fetchLockEvents - FilterCrossChainEvent error :%s", err.Error())
		return false
	}
	if iter == nil {
		debug("QuorumManager fetchLockEvents - no event iter found on FilterCrossChainEvent")
		return false
	}

	for iter.Next() {
		evt := iter.Event
		addr := evt.ProxyOrAssetContract
		if !m.config.TargetContracts.CheckContract(addr, "outbound", evt.ToChainId) {
			continue
		}

		param := recoverMakeTxParams(evt.Rawdata)
		if !m.checkCrossChainEvent(param) {
			continue
		}

		_, sink := serializeCrossTransfer(evt, height)
		if err := m.db.PutRetry(sink.Bytes()); err != nil {
			log.Errorf("QuorumManager fetchLockEvents - m.db.PutRetry error: %s", err)
		} else {
			log.Infof("QuorumManager fetchLockEvents -  height: %d", height)
		}
	}
	return true
}

// handleDepositEvents
func (m *QuorumManager) handleDepositEvents(refHeight uint64) error {
	retryList, err := m.db.GetAllRetry()
	if err != nil {
		return fmt.Errorf("handleDepositEvents - m.db.GetAllRetry error: %s", err)
	}

	for _, v := range retryList {
		crossTx, err := deserializeCrossTransfer(v)
		if err != nil {
			log.Errorf("QuorumManager handleDepositEvents - retry.Deserialization error: %s", err)
			continue
		}

		// poly do not allow to verify header with validators in old epoch,
		// we need to waiting for some blocks to fetch the latest block header and proof.
		// and quorum only add/del single node in one epoch.
		// safeHeight used for avoid chain fork, just need 1 block.
		distance := m.safeBlockDistance()
		if refHeight-distance <= crossTx.height {
			log.Infof("QuorumManager handleDepositEvents - ignore tx %s, refHeight %d - distance %d <= crossTx height %d",
				crossTx.txIndex, refHeight, distance, crossTx.height)
			continue
		}
		safeHeight := refHeight - 1

		// get proof from quorum chain
		proof, hdr, err := m.getProof(crossTx, safeHeight)
		if err != nil {
			log.Errorf("QuorumManager handleDepositEvents - get proof error :%s\n", err.Error())
			continue
		}

		// commit proof to poly chain success
		txHash, err := m.commitProof(uint32(safeHeight), proof, crossTx.value, crossTx.txId, hdr)
		if err != nil {
			if strings.Contains(err.Error(), "chooseUtxos, current utxo is not enough") {
				log.Infof("QuorumManager handleDepositEvents - invokeNativeContract error: %s", err)
			} else if strings.Contains(err.Error(), "tx already done") {
				log.Infof("QuorumManager handleDepositEvents - plt_tx %s already on poly", txIdHex(crossTx.txId))
				if err := m.db.DeleteRetry(v); err != nil {
					log.Errorf("QuorumManager handleDepositEvents - deleteRetry error: %s", err)
				}
			} else {
				log.Errorf("QuorumManager handleDepositEvents - invoke NativeContract for block %d eth_tx %s: %s, err %s",
					safeHeight, txIdHex(crossTx.txId), err)
			}
			continue
		}

		// process cache
		if err := m.db.PutCheck(txHash, v); err != nil {
			log.Errorf("QuorumManager handleDepositEvents - this.db.PutCheck error: %s", err)
		}
		if err := m.db.DeleteRetry(v); err != nil {
			log.Errorf("QuorumManager handleDepositEvents - this.db.PutCheck error: %s", err)
		}
		log.Infof("QuorumManager handleDepositEvents - %s", crossTx.txIndex)
	}
	return nil
}

func (m *QuorumManager) getProof(e *CrossTransfer, height uint64) (proof []byte, hdr []byte, err error) {
	// decode events
	keyBytes, err := getMappingKey(e.txIndex)
	if err != nil {
		return
	}
	proofKey := hexutil.Encode(keyBytes)
	heightHex := uint64ToHex(height)

	// get proof from quorum chain
	proof, err = quorum.GetProof(m.eccdContract(), proofKey, heightHex)
	if err != nil {
		return
	}

	var block *sctyp.Block
	block, err = m.quorumClient.BlockByNumber(context.Background(), uint64ToBig(height))
	if err != nil {
		return
	}

	hdr, err = block.Header().MarshalJSON()
	return
}

func (m *QuorumManager) commitProof(
	height uint32,
	proof []byte,
	txData []byte,
	txhash []byte,
	hdr []byte,
) (string, error) {

	debug("QuorumManager - commit proof, height: %d, proof: %s, txData: %s, txhash: %s",
		height, string(proof), hex.EncodeToString(txData), hex.EncodeToString(txhash))

	sideChainId := m.sideChainID()
	relayAddr := sccm.Hex2Bytes(m.polySigner.Address.ToHexString())
	tx, err := m.polySdk.Native.Ccm.ImportOuterTransfer(
		sideChainId,
		txData,
		height,
		proof,
		relayAddr,
		hdr,
		m.polySigner,
	)
	if err != nil {
		return "", err
	}

	debug("QuorumManager - commitProof debug:"+
		" hash %s, header %s, txData %s, proof %s, height %d",
		sccm.BytesToHash(txhash).Hex(),
		hexutil.Encode(hdr),
		hexutil.Encode(txData),
		hexutil.Encode(proof),
		height,
	)

	log.Infof("QuorumManager commitProof - send transaction to poly chain: "+
		"( poly_txhash: %s, plt_txhash: %s, height: %d )",
		tx.ToHexString(), sccm.BytesToHash(txhash).String(), height)

	return tx.ToHexString(), nil
}

func (m *QuorumManager) checkLockEvents() error {
	checkMap, err := m.db.GetAllCheck()
	if err != nil {
		return fmt.Errorf("checkLockEvents - m.db.GetAllCheck error: %s", err)
	}

	for txhash, v := range checkMap {
		event, err := m.polySdk.GetSmartContractEvent(txhash)
		if err != nil {
			log.Errorf("QuorumManager checkLockEvents - m.aliaSdk.GetSmartContractEvent error: %s", err)
			continue
		}
		if event == nil {
			continue
		}

		if event.State != 1 {
			log.Errorf("QuorumManager checkLockEvents - state of poly tx %s is failed", txhash)
			if err := m.db.PutRetry(v); err != nil {
				log.Errorf("QuorumManager checkLockEvents - m.db.PutRetry error:%s", err)
			}
		}

		if err = m.db.DeleteCheck(txhash); err != nil {
			log.Errorf("QuorumManager checkLockEvents - m.db.DeleteRetry error:%s", err)
		}

		log.Infof("QuorumManager checkLockEvents - state of poly tx %s is success!", txhash)
	}
	return nil
}

// checkCrossChainEvent return false if cross chain event from quorum lock proxy contract
// is already existed in poly chain.
func (m *QuorumManager) checkCrossChainEvent(param *ccm.MakeTxParam) bool {
	key := m.formatStorageKey(ccm.DONE_TX, param.CrossChainID)
	raw, _ := m.polySdk.GetStorage(polyCrossChainMgrContract.ToHexString(), key)
	if len(raw) != 0 {
		log.Debugf("QuorumManager fetchLockEvents - ccid %s (tx_hash: %s) already on poly",
			hex.EncodeToString(param.CrossChainID), sccm.BytesToHash(param.TxHash))
		return false
	}
	return true
}

func (m *QuorumManager) formatStorageKey(prefix string, content []byte) []byte {
	key := []byte(prefix)
	chainID := m.sideChainID()
	key = append(key, autils.GetUint64Bytes(chainID)...)
	if content != nil {
		key = append(key, content...)
	}
	return key
}

func (m *QuorumManager) eccdContract() string {
	return m.config.QuorumConfig.ECCDContractAddress
}

func (m *QuorumManager) eccmContract() string {
	return m.config.QuorumConfig.ECCMContractAddress
}

// usually add/del single node need 4 blocks, and relayer should waiting for at least 1 block to avoid quorum chain fork.
const defaultDistance = 6

func (m *QuorumManager) safeBlockDistance() uint64 {
	if m.config.QuorumConfig.BlockConfig < defaultDistance {
		return defaultDistance
	} else {
		return m.config.QuorumConfig.BlockConfig
	}
}

func (m *QuorumManager) sideChainID() uint64 {
	return m.config.QuorumConfig.SideChainId
}
