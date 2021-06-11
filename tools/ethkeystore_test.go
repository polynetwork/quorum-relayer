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
package tools

import (
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/polynetwork/quorum-relayer/config"
	"math/big"
	"testing"
)

func TestETHSigner_SignTransaction(t *testing.T) {
	cfg := config.NewServiceConfig("./config-debug.json")
	ethsigner := NewEthKeyStore(cfg.QuorumConfig, big.NewInt(105))
	tx := &types.Transaction{}
	tx, err := ethsigner.SignTransaction(tx, accounts.Account{})
	if err != nil {
		t.Fatal(err)
	}
	v, r, s := tx.RawSignatureValues()
	if v.BitLen()+r.BitLen()+s.BitLen() <= 0 {
		t.Fatal("failed to sign")
	}
}
