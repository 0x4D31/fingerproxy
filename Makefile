TARGET = fingerproxy

build: build_darwin_arm64 build_darwin_amd64 \
	build_linux_amd64 build_linux_arm build_linux_arm64 \
	build_windows_amd64 build_windows_arm64

build_darwin_%: GOOS = darwin
build_linux_%: GOOS = linux
build_windows_%: GOOS = windows
build_windows_%: EXT = .exe

build_%_amd64: GOARCH = amd64
build_%_arm: GOARCH = arm
build_%_arm64: GOARCH = arm64

COMMIT = $(shell git rev-parse --short HEAD || true)
TAG = $(shell git describe --tags --abbrev=0 HEAD 2>/dev/null || true)
BINDIR = bin
BINPATH = $(BINDIR)/$(TARGET)_$(GOOS)_$(GOARCH)$(EXT)

build_%:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(BINPATH) \
		-ldflags "-X main.buildCommit=$(COMMIT) -X main.buildVersion=$(TAG)" \
		-gcflags "./...=-m" \
		-gcflags "./pkg/http2=" \
		./cmd

	chmod +x $(BINPATH)

sha256sum:
	cd $(BINDIR) && sha256sum $(TARGET)_* > $(TARGET).sha256sum

PKG_LIST = $(shell go list ./... | grep -v github.com/0x4D31/fingerproxy/pkg/http2)
test:
	@go test -v $(PKG_LIST)

benchmark:
	@go test -v $(PKG_LIST) -run=NONE -bench=^Benchmark -benchmem -count=3 -cpu=2
