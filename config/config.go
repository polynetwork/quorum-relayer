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
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common/password"
	"github.com/polynetwork/quorum-relayer/log"
	"github.com/polynetwork/quorum-relayer/utils/keystore"
)

const (
	PLT_MONITOR_INTERVAL = time.Second
	ONT_MONITOR_INTERVAL = time.Second

	PLT_PROOF_USERFUL_BLOCK  = 1
	ONT_USEFUL_BLOCK_NUM     = 1
	DEFAULT_CONFIG_FILE_NAME = "./config.json"
	Version                  = "1.0"

	DEFAULT_LOG_LEVEL = log.InfoLog
)

var Debug bool = false

type ServiceConfig struct {
	Workspace       string
	PolyConfig      *PolyConfig
	QuorumConfig    *QuorumConfig
	BoltDbPath      string
	RoutineNum      int64
	TargetContracts TargetContracts
}

func (c *ServiceConfig) PolyWalletPath() string {
	if path.IsAbs(c.PolyConfig.WalletFile) {
		return c.PolyConfig.WalletFile
	}
	return path.Join(c.Workspace, c.PolyConfig.WalletFile)
}

func (c *ServiceConfig) QuorumKeystorePath() string {
	if path.IsAbs(c.QuorumConfig.KeyStorePath) {
		return c.QuorumConfig.KeyStorePath
	}
	return path.Join(c.Workspace, c.QuorumConfig.KeyStorePath)
}

func (c *ServiceConfig) BoltDBPath() string {
	if path.IsAbs(c.BoltDbPath) {
		return c.BoltDbPath
	}
	return path.Join(c.Workspace, c.BoltDbPath)
}

type TargetContracts []map[common.Address]ChainIDArr

func (s TargetContracts) CheckContract(toContract common.Address, ChainIdField string, chainID uint64) bool {
	for _, v := range s[:] {
		for addr, arr := range v {
			if bytes.Equal(addr.Bytes(), toContract.Bytes()) && arr.IsChainID(chainID, ChainIdField) {
				return true
			}
		}
		//arr, ok := v[toContract]
		//if ok && arr.IsChainID(chainID, ChainIdField) {
		//	return true
		//}
	}
	return false
}

type ChainIDArr map[string][]uint64

func (a ChainIDArr) IsChainID(dstChainId uint64, field string) bool {
	if len(a[field]) == 0 {
		return true
	}

	for _, id := range a[field] {
		if id == dstChainId {
			return true
		}
	}
	return false
}

type PolyConfig struct {
	RestURL                 string
	EntranceContractAddress string
	WalletFile              string
	WalletPwd               string
}

func (c *ServiceConfig) OpenPolyWallet(polySdk *sdk.PolySdk) (signer *sdk.Account, err error) {
	var wallet *sdk.Wallet

	if wallet, err = polySdk.OpenWallet(c.PolyWalletPath()); err != nil {
		return nil, fmt.Errorf("open wallet error: %s", err.Error())
	}

	pwd := []byte(c.PolyConfig.WalletPwd)
	if signer, err = wallet.GetDefaultAccount(pwd); err != nil || signer == nil {
		if signer, err = wallet.NewDefaultSettingAccount(pwd); err != nil {
			return nil, fmt.Errorf("wallet password error: %s", err.Error())
		}
		if err = wallet.Save(); err != nil {
			return nil, err
		}
	}

	return signer, nil
}

type QuorumConfig struct {
	SideChainId         uint64
	RestURL             string
	ECCMContractAddress string
	ECCDContractAddress string
	KeyStorePath        string
	KeyStorePwdSet      map[string]string
	BlockConfig         uint64
	HeadersPerBatch     int
}

func (c *ServiceConfig) ImportQuorumAccount(chainId *big.Int) (
	*keystore.QuorumKeyStore, []accounts.Account, error) {

	ks, err := keystore.NewQuorumKeyStore(c.QuorumKeystorePath(), chainId)
	if err != nil {
		return nil, nil, err
	}

	accArr := ks.GetAccounts()
	pwdSet := c.QuorumConfig.KeyStorePwdSet
	if len(pwdSet) == 0 {
		fmt.Println("please input the passwords for ethereum keystore: ")
		for _, v := range accArr {
			fmt.Printf("For address %s. ", v.Address.String())
			raw, err := password.GetPassword()
			if err != nil {
				log.Fatalf("failed to input password: %v", err)
				panic(err)
			}
			pwdSet[strings.ToLower(v.Address.String())] = string(raw)
		}
	}
	if err = ks.UnlockKeys(pwdSet); err != nil {
		return nil, nil, err
	}

	return ks, accArr, nil
}

func ReadFile(fileName string) ([]byte, error) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: open file %s error %s", fileName, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Errorf("ReadFile: File %s close error %s", fileName, err)
		}
	}()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: ioutil.ReadAll %s error %s", fileName, err)
	}
	return data, nil
}

func NewServiceConfig(configFilePath string) *ServiceConfig {
	fileContent, err := ReadFile(configFilePath)
	if err != nil {
		log.Errorf("NewServiceConfig: failed, err: %s", err)
		return nil
	}

	cfg := &ServiceConfig{}
	if err = json.Unmarshal(fileContent, cfg); err != nil {
		log.Errorf("NewServiceConfig: failed, err: %s", err)
		return nil
	}

	for k, v := range cfg.QuorumConfig.KeyStorePwdSet {
		delete(cfg.QuorumConfig.KeyStorePwdSet, k)
		cfg.QuorumConfig.KeyStorePwdSet[strings.ToLower(k)] = v
	}

	return cfg
}
