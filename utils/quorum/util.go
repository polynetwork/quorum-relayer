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
package quorum

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/polynetwork/quorum-relayer/utils/rest"
)

var (
	once     = new(sync.Once)
	cli      *rest.RestClient
	version  string
	clientID uint
)

func Initialize(_url string, _cli *rest.RestClient) {
	once.Do(func() {
		cli = _cli
		cli.SetAddr(_url)
		clientID = 1
		version = "2.0"
	})
}

func GetNodeHeader(height uint64) ([]byte, error) {
	params := []interface{}{fmt.Sprintf("0x%x", height), true}
	req := &blockReq{
		JsonRpc: version,
		Method:  "eth_getBlockByNumber",
		Params:  params,
		Id:      clientID,
	}
	reqDat, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("GetNodeHeight: marshal req err: %s", err)
	}
	rspDat, err := cli.SendRestRequest(reqDat)
	if err != nil {
		return nil, fmt.Errorf("GetNodeHeight err: %s", err)
	}

	rsp := &blockRsp{}
	err = json.Unmarshal(rspDat, rsp)
	if err != nil {
		return nil, fmt.Errorf("GetNodeHeight, unmarshal resp err: %s", err)
	}
	if rsp.Error != nil {
		return nil, fmt.Errorf("GetNodeHeight, unmarshal resp err: %s", rsp.Error.Message)
	}

	block, err := json.Marshal(rsp.Result)
	if err != nil {
		return nil, fmt.Errorf("GetNodeHeight, unmarshal header err: %s", err)
	} else {
		return block, nil
	}
}

func GetNodeHeight() (uint64, error) {
	req := &heightReq{
		JsonRpc: version,
		Method:  "eth_blockNumber",
		Params:  make([]string, 0),
		Id:      clientID,
	}
	reqData, err := json.Marshal(req)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight: marshal req err: %s", err)
	}
	rspData, err := cli.SendRestRequest(reqData)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight err: %s", err)
	}

	rsp := &heightRsp{}
	err = json.Unmarshal(rspData, rsp)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight, unmarshal resp err: %s", err)
	}
	if rsp.Error != nil {
		return 0, fmt.Errorf("GetNodeHeight, unmarshal resp err: %s", rsp.Error.Message)
	}

	height, err := strconv.ParseUint(rsp.Result, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight, parse resp height %s failed", rsp.Result)
	} else {
		return height, nil
	}
}

func GetProof(contractAddress string, key string, blockHeight string) ([]byte, error) {
	req := &proofReq{
		JsonRPC: version,
		Method:  "eth_getProof",
		Params:  []interface{}{contractAddress, []string{key}, blockHeight},
		Id:      clientID,
	}
	reqDat, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("get_ethproof: marshal req err: %s", err)
	}
	rspDat, err := cli.SendRestRequest(reqDat)
	if err != nil {
		return nil, fmt.Errorf("GetProof: send request err: %s", err)
	}

	rsp := &proofRsp{}
	err = json.Unmarshal(rspDat, rsp)
	if err != nil {
		return nil, fmt.Errorf("GetProof, unmarshal resp err: %s", err)
	}
	if rsp.Error != nil {
		return nil, fmt.Errorf("GetProof, unmarshal resp err: %s", rsp.Error.Message)
	}

	result, err := json.Marshal(rsp.Result)
	if err != nil {
		return nil, fmt.Errorf("GetProof, Marshal result err: %s", err)
	}
	return result, nil
}
