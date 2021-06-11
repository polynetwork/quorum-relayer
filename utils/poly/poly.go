/*
 * Copyright (C) 2020 The poly network Authors
 * This file is part of The poly network library.
 *
 * The  poly network  is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The  poly network  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License
 * along with The poly network .  If not, see <http://www.gnu.org/licenses/>.
 */
package poly

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	polycm "github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	"github.com/polynetwork/poly/core/signature"
	"github.com/polynetwork/poly/core/types"
	"github.com/polynetwork/poly/native/service/header_sync/ont"
)

func VerifySig(hash common.Hash, multiSigData []byte, keepers []common.Address, m int) error {
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

func RecoverSignersFromMultiSigs(hash common.Hash, sigs [][]byte) ([]common.Address, error) {
	signers := make([]common.Address, len(sigs))
	for i := 0; i < len(sigs); i++ {
		sig := sigs[i]
		enc, err := crypto.Ecrecover(hash[:], sig)
		if err != nil {
			return nil, err
		}
		signer := common.BytesToAddress(enc)

		//temp, _ := polycm.AddressParseFromBytes(enc)
		fmt.Println("keeper", signer.Hex()) //temp.ToBase58())

		signers[i] = signer
	}

	return signers, nil
}

func DeserializeKeepers(raw []byte) []common.Address {
	source := polycm.NewZeroCopySource(raw)
	keeperLen, _ := source.NextUint64()
	keepers := make([]common.Address, keeperLen)

	for i := 0; i < int(keeperLen); i++ {
		keeperBytes, _ := source.NextVarBytes()
		addr := common.BytesToAddress(keeperBytes)

		// todo
		//temp, _ := polycm.AddressParseFromBytes(keeperBytes)
		fmt.Println("keeper", addr.Hex()) //temp.ToBase58())

		keepers[i] = addr
	}
	return keepers
}

func ConvertAddr(base58Addr string) common.Address {
	addr, _ := polycm.AddressFromBase58(base58Addr)
	return common.BytesToAddress(addr[:])
}

func containsMAddress(signers, contains []common.Address, m int) bool {
	in := func(addr common.Address) bool {
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

func VerifyPolyHeader(hdr *types.Header, peers *ont.ConsensusPeers) error {
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
	if err := signature.VerifyMultiSignature(
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
