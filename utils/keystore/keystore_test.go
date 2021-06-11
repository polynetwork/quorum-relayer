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
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
)

func TestETHSigner_SignTransaction(t *testing.T) {
	keystorePath := "./config-debug.json"
	cid := big.NewInt(100)

	signer, err := NewQuorumKeyStore(keystorePath, cid)
	assert.NoError(t, err)

	tx := &types.Transaction{}
	acc := signer.GetAccounts()[0]
	signedTx, err := signer.SignTransaction(tx, acc)
	assert.NoError(t, err)

	v, r, s := signedTx.RawSignatureValues()
	if v.BitLen()+r.BitLen()+s.BitLen() <= 0 {
		t.Fatal("failed to sign")
	}
}

func TestSimple(t *testing.T) {
	expect := "0x808d6D8d832202c0570171E720da2EaA54D4fD07"
	addr := common.HexToAddress(expect)
	t.Log(addr.Hex())
	assert.Equal(t, expect, addr.Hex())
}
