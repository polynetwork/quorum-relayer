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
package keystore

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/polynetwork/quorum-relayer/log"
)

type QuorumKeyStore struct {
	keyStore *keystore.KeyStore
	chainId  *big.Int
}

func NewQuorumKeyStore(keystorePath string,
	chainId *big.Int) (*QuorumKeyStore, error) {

	service := &QuorumKeyStore{
		chainId: chainId,
		keyStore: keystore.NewKeyStore(
			keystorePath,
			keystore.StandardScryptN,
			keystore.StandardScryptP,
		),
	}

	accArr := service.keyStore.Accounts()
	if len(accArr) == 0 {
		return nil, fmt.Errorf("relayer has no account")
	}

	str := ""
	for i, v := range accArr {
		str += fmt.Sprintf("(no.%d acc: %s), \r\n", i+1, v.Address.Hex())
	}
	log.Infof("relayer are using accounts:\r\n [ %s ]", str)

	return service, nil
}

func (s *QuorumKeyStore) UnlockKeys(pwds map[string]string) error {
	for _, v := range s.GetAccounts() {
		addr := strings.ToLower(v.Address.String())
		pwd := pwds[addr]
		if err := s.keyStore.Unlock(v, pwd); err != nil {
			return fmt.Errorf("failed to unlock eth acc %s: %v", v.Address.String(), err)
		}
	}
	return nil
}

func (s *QuorumKeyStore) SignTransaction(
	tx *types.Transaction,
	acc accounts.Account,
) (*types.Transaction, error) {
	return s.keyStore.SignTx(acc, tx, s.chainId)
}

func (s *QuorumKeyStore) GetAccounts() []accounts.Account {
	return s.keyStore.Accounts()
}

func (s *QuorumKeyStore) GetChainId() uint64 {
	return s.chainId.Uint64()
}
