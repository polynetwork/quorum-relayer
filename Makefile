# Go parameters
GOCMD=GO111MODULE=on go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test

prepare:
	mkdir -p build/Log
	mkdir -p build/boltdb

compile:
	$(GOBUILD) -o build/relayer main.go

compile-linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o build/relayer-linux main.go

run:
	@echo test case $(pltforce) $(polyforce)
	#./build/relayer --paletteforce $(pltforce) --poly $(polyforce) --logdir build/Log/ --config build/config.json
	./build/relayer --logdir build/Log/ --config build/config.json

clean:
	rm -rf build/Log/*

clear:
	rm -rf build/Log build/relayer build/boltdb