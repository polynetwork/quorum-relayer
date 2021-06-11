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
package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	sccli "github.com/ethereum/go-ethereum/ethclient"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/quorum-relayer/cmd"
	"github.com/polynetwork/quorum-relayer/config"
	"github.com/polynetwork/quorum-relayer/db"
	"github.com/polynetwork/quorum-relayer/log"
	"github.com/polynetwork/quorum-relayer/manager"
	"github.com/urfave/cli"
)

var (
	ConfigPath,
	LogDir string

	StartHeight,
	PolyStartHeight,
	StartForceHeight uint64
)

func setupApp() *cli.App {
	app := cli.NewApp()
	app.Usage = "ETH relayer Service"
	app.Action = startServer
	app.Version = config.Version
	app.Copyright = "Copyright in 2019 The Ontology Authors"
	app.Flags = []cli.Flag{
		cmd.LogLevelFlag,
		cmd.ConfigPathFlag,
		cmd.SideChainStartFlag,
		cmd.SideChainStartForceFlag,
		cmd.PolyStartFlag,
		cmd.DebugFlag,
		cmd.LogDir,
	}
	app.Commands = []cli.Command{}
	app.Before = func(context *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		return nil
	}
	return app
}

func startServer(ctx *cli.Context) {
	// settle log config
	logLevel := ctx.GlobalInt(cmd.GetFlagName(cmd.LogLevelFlag))
	ld := ctx.GlobalString(cmd.GetFlagName(cmd.LogDir))
	log.InitLog(logLevel, ld, log.Stdout)

	// settle config path
	ConfigPath = ctx.GlobalString(cmd.GetFlagName(cmd.ConfigPathFlag))

	// settle poly and quorum chain height
	if value := ctx.GlobalUint64(cmd.GetFlagName(cmd.SideChainStartFlag)); value > 0 {
		StartHeight = value
	}
	if value := ctx.GlobalUint64(cmd.GetFlagName(cmd.SideChainStartForceFlag)); value > 0 {
		StartForceHeight = value
	}
	if value := ctx.GlobalUint64(cmd.GetFlagName(cmd.PolyStartFlag)); value > 0 {
		PolyStartHeight = value
	}
	if value := ctx.GlobalBool(cmd.GetFlagName(cmd.DebugFlag)); value {
		config.Debug = true
	}

	// read config
	srvConfig := config.NewServiceConfig(ConfigPath)
	if srvConfig == nil {
		log.Errorf("startServer - create config failed!")
		return
	}

	// create poly sdk
	polySdk := sdk.NewPolySdk()
	if err := setUpPoly(polySdk, srvConfig.PolyConfig.RestURL); err != nil {
		log.Errorf("startServer - failed to setup poly sdk: %v", err)
		return
	}

	// create quorum sdk
	sideChainSDK, err := sccli.Dial(srvConfig.QuorumConfig.RestURL)
	if err != nil {
		log.Errorf("startServer - cannot dial sync node, err: %s", err)
		return
	}

	var boltDB *db.BoltDB
	if srvConfig.BoltDbPath == "" {
		boltDB, err = db.NewBoltDB("boltdb")
	} else {
		boltDB, err = db.NewBoltDB(srvConfig.BoltDBPath())
	}
	if err != nil {
		log.Fatalf("db.NewWaitingDB error:%s", err)
		return
	}

	initPolyServer(srvConfig, polySdk, sideChainSDK, boltDB)
	initSideChainServer(srvConfig, polySdk, sideChainSDK, boltDB)
	waitToExit()
}

func setUpPoly(poly *sdk.PolySdk, RpcAddr string) error {
	poly.NewRpcClient().SetAddress(RpcAddr)
	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	poly.SetChainId(hdr.ChainID)
	return nil
}

func waitToExit() {
	exit := make(chan bool, 0)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sc {
			log.Infof("waitToExit - ETH relayer received exit signal:%v.", sig.String())
			close(exit)
			break
		}
	}()
	<-exit
}

func initSideChainServer(
	srvConfig *config.ServiceConfig,
	polySDK *sdk.PolySdk,
	sideChainSDK *sccli.Client,
	boltDB *db.BoltDB,
) {

	mgr, err := manager.NewQuorumManager(
		srvConfig,
		StartHeight,
		StartForceHeight,
		polySDK,
		sideChainSDK,
		boltDB,
	)
	if err != nil {
		panic(fmt.Sprintf("initSideChainServer - eth service start err: %s", err.Error()))
	}

	go mgr.MonitorChain()
	go mgr.MonitorDeposit()
	go mgr.CheckDeposit()
}

func initPolyServer(
	srvConfig *config.ServiceConfig,
	polySDK *sdk.PolySdk,
	sideChainSDK *sccli.Client,
	boltDB *db.BoltDB,
) {

	mgr, err := manager.NewPolyManager(
		srvConfig,
		uint32(PolyStartHeight),
		polySDK,
		sideChainSDK,
		boltDB,
	)
	if err != nil {
		panic(fmt.Sprintf("initPolyServer - PolyServer service start failed: %v", err))
	}

	go mgr.MonitorChain()
}

func main() {
	log.Infof("main - ETH relayer starting...")
	if err := setupApp().Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
