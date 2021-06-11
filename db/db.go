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
package db

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path"
	"strings"
	"sync"

	"github.com/boltdb/bolt"
)

const (
	maxNum   = 1000
	capacity = 500000
)

var (
	// buckets name
	bktCheck        = []byte("Check")
	bktRetry        = []byte("Retry")
	bktPolyHeight   = []byte("PolyHeight")
	bktQuorumHeight = []byte("QuorumHeight")
	bktQuorumValSet = []byte("QuorumValSet")

	// key for quorum validators
	validatorsKey = []byte("quorum_validators")

	// key for poly height
	polyHeightKey   = []byte("poly_height")
	quorumHeightKey = []byte("quorum_height")

	// empty value
	emptyValue = []byte{0x00}
)

var (
	ErrOutOfNumber = errors.New("out of max number")
)

type BoltDB struct {
	mtx      *sync.RWMutex
	db       *bolt.DB
	filePath string
}

func NewBoltDB(filePath string) (*BoltDB, error) {
	if !strings.Contains(filePath, ".bin") {
		filePath = path.Join(filePath, "bolt.bin")
	}

	opt := &bolt.Options{InitialMmapSize: capacity}
	db, err := bolt.Open(filePath, 0644, opt)
	if err != nil {
		return nil, err
	}

	w := &BoltDB{
		mtx:      new(sync.RWMutex),
		db:       db,
		filePath: filePath,
	}

	list := [][]byte{
		bktCheck,
		bktRetry,
		bktPolyHeight,
		bktQuorumHeight,
		bktQuorumValSet,
	}
	for _, name := range list {
		if err := w.create(name); err != nil {
			return nil, err
		}
	}

	return w, nil
}

func (w *BoltDB) PutCheck(txHash string, v []byte) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	handle := func(bkt *bolt.Bucket) error {
		k, err := hex.DecodeString(txHash)
		if err != nil {
			return err
		}
		return bkt.Put(k, v)
	}

	return w.update(bktCheck, handle)
}

func (w *BoltDB) DeleteCheck(txHash string) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	handle := func(bkt *bolt.Bucket) error {
		k, err := hex.DecodeString(txHash)
		if err != nil {
			return err
		}
		return bkt.Delete(k)
	}

	return w.update(bktCheck, handle)
}

func (w *BoltDB) PutRetry(k []byte) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	handle := func(bkt *bolt.Bucket) error {
		return bkt.Put(k, emptyValue)
	}

	return w.update(bktRetry, handle)
}

func (w *BoltDB) DeleteRetry(k []byte) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	handle := func(bkt *bolt.Bucket) error {
		return bkt.Delete(k)
	}

	return w.update(bktRetry, handle)
}

func (w *BoltDB) GetAllCheck() (map[string][]byte, error) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	checkMap := make(map[string][]byte)

	handle := func(k, v []byte) error {
		_k, _v := copyBytes(k), copyBytes(v)
		checkMap[hex.EncodeToString(_k)] = _v
		if len(checkMap) >= maxNum {
			return ErrOutOfNumber
		}
		return nil
	}

	if err := w.foreach(bktCheck, handle); err != nil {
		return nil, err
	}

	return checkMap, nil
}

func (w *BoltDB) GetAllRetry() ([][]byte, error) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	retryList := make([][]byte, 0)

	handle := func(k, _ []byte) error {
		_k := copyBytes(k)
		retryList = append(retryList, _k)
		if len(retryList) >= maxNum {
			return ErrOutOfNumber
		}
		return nil
	}

	if err := w.foreach(bktRetry, handle); err != nil {
		return nil, err
	} else {
		return retryList, nil
	}
}

func (w *BoltDB) UpdatePolyHeight(h uint32) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	handle := func(bkt *bolt.Bucket) error {
		raw := make([]byte, 4)
		binary.LittleEndian.PutUint32(raw, h)
		return bkt.Put(polyHeightKey, raw)
	}

	return w.update(bktPolyHeight, handle)
}

func (w *BoltDB) GetPolyHeight() uint32 {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	var h uint32 = 0
	handle := func(raw []byte) error {
		if len(raw) > 0 {
			h = binary.LittleEndian.Uint32(raw)
		}
		return nil
	}

	_ = w.read(bktPolyHeight, polyHeightKey, handle)

	return h
}

func (w *BoltDB) UpdateQuorumHeight(h uint64) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	handle := func(bkt *bolt.Bucket) error {
		raw := make([]byte, 8)
		binary.LittleEndian.PutUint64(raw, h)
		return bkt.Put(quorumHeightKey, raw)
	}

	return w.update(bktQuorumHeight, handle)
}

func (w *BoltDB) GetQuorumHeight() uint64 {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	var h uint64 = 0
	handle := func(raw []byte) error {
		if len(raw) > 0 {
			h = binary.LittleEndian.Uint64(raw)
		}
		return nil
	}

	_ = w.read(bktQuorumHeight, quorumHeightKey, handle)
	return h
}

func (w *BoltDB) PutValSet(valset []byte) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	handle := func(bkt *bolt.Bucket) error {
		return bkt.Put(validatorsKey, valset)
	}

	return w.update(bktQuorumValSet, handle)
}

func (w *BoltDB) GetValSet() ([]byte, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	var enc []byte
	handle := func(raw []byte) error {
		enc = copyBytes(raw)
		return nil
	}
	_ = w.read(bktQuorumValSet, validatorsKey, handle)

	return enc, nil
}

func (w *BoltDB) Close() {
	w.mtx.Lock()
	_ = w.db.Close()
	w.mtx.Unlock()
}

type (
	readHandler    func(raw []byte) error
	updateHandler  func(bkt *bolt.Bucket) error
	foreachHandler func(k, v []byte) error
)

func (w *BoltDB) create(name []byte) error {
	return w.db.Update(func(btx *bolt.Tx) error {
		_, err := btx.CreateBucketIfNotExists(name)
		return err
	})
}

func (w *BoltDB) read(bktName, fieldName []byte, handler readHandler) error {
	return w.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktName)
		raw := bkt.Get(fieldName)
		if handler == nil {
			return nil
		}
		return handler(raw)
	})
}

func (w *BoltDB) update(bktName []byte, handler updateHandler) error {
	return w.db.Update(func(btx *bolt.Tx) error {
		bucket := btx.Bucket(bktName)
		if handler == nil {
			return nil
		}
		return handler(bucket)
	})
}

func (w *BoltDB) foreach(bktName []byte, handler foreachHandler) error {
	return w.db.Update(func(btx *bolt.Tx) error {
		bkt := btx.Bucket(bktName)
		if handler == nil {
			return nil
		}
		_ = bkt.ForEach(func(k, v []byte) error {
			return handler(k, v)
		})
		return nil
	})
}

func copyBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
