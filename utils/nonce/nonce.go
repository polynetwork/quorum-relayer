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
package nonce

import (
	"context"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	pltcli "github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/quorum-relayer/log"
)

type NonceManager struct {
	online map[common.Address]uint64   // the nonce obtained on chain stored in `online` map first.
	backup map[common.Address][]uint64 // if nonce is bigger than current nonce, the value will append in the `backup` list for future usage.
	client *pltcli.Client
	mtx    *sync.Mutex
}

func NewNonceManager(ethClient *pltcli.Client) *NonceManager {
	return &NonceManager{
		online: make(map[common.Address]uint64),
		backup: make(map[common.Address][]uint64),
		client: ethClient,
		mtx:    new(sync.Mutex),
	}
}

// UseNonce get nonce on chain if it not exist in `backup` list.
func (m *NonceManager) UseNonce(address common.Address) uint64 {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// get minimum nonce which located at the head of `backup` list.
	// and right shift the `backup` list for next usage.
	if len(m.backup[address]) > 0 {
		nonce := m.backup[address][0]
		m.backup[address] = m.backup[address][1:]
		return nonce
	}

	// get nonce on chain and set it in `online` map
	nonce, ok := m.online[address]
	if !ok {
		uintNonce, err := m.client.PendingNonceAt(context.Background(), address)
		if err != nil {
			log.Errorf("failed to get %s nonce, err: %s, set it to 0!", address, err)
		}
		m.online[address] = uintNonce
		nonce = uintNonce
	}

	// increase record
	m.online[address]++
	return nonce
}

func (m *NonceManager) ReturnNonce(addr common.Address, nonce uint64) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	list, ok := m.backup[addr]
	if !ok {
		list = make([]uint64, 0)
	}
	list = append(list, nonce)

	sort.Slice(list, func(i, j int) bool {
		return list[i] < list[j]
	})
	m.backup[addr] = list
}
