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
package rest

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const (
	KeepAlive = false
	TlsOpen   = true

	MaxIdleConns    = 5
	IdleConnTimeout = 300 * time.Second
	ResponseTimeout = 300 * time.Second
	RequestTimeout  = 300 * time.Second
)

type RestClient struct {
	addr string
	cli  *http.Client
}

func NewRestClient() *RestClient {
	transport := &http.Transport{
		MaxIdleConnsPerHost:   MaxIdleConns,
		DisableKeepAlives:     KeepAlive,
		IdleConnTimeout:       IdleConnTimeout,
		ResponseHeaderTimeout: ResponseTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: TlsOpen},
	}

	return &RestClient{
		cli: &http.Client{
			Transport: transport,
			Timeout:   RequestTimeout,
		},
	}
}

func (r *RestClient) SetAddr(addr string) *RestClient {
	r.addr = addr
	return r
}

func (r *RestClient) GetAddr() string {
	return r.addr
}

func (r *RestClient) SetRestClient(restClient *http.Client) *RestClient {
	r.cli = restClient
	return r
}

func (r *RestClient) SendRestRequest(data []byte) ([]byte, error) {
	resp, err := r.cli.Post(r.addr, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", data, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rest response body error:%s", err)
	}
	return body, nil
}
