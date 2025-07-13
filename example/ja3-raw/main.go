package main

import (
	"fmt"

	"github.com/0x4D31/fingerproxy"
	"github.com/0x4D31/fingerproxy/pkg/fingerprint"
	"github.com/0x4D31/fingerproxy/pkg/ja3"
	"github.com/0x4D31/fingerproxy/pkg/metadata"
	"github.com/0x4D31/fingerproxy/pkg/reverseproxy"
	"github.com/dreadl0ck/tlsx"
)

func main() {
	fingerproxy.GetHeaderInjectors = func() []reverseproxy.HeaderInjector {
		i := fingerproxy.DefaultHeaderInjectors()
		i = append(i, fingerprint.NewFingerprintHeaderInjector(
			"X-JA3-Raw-Fingerprint",
			fpJA3Raw,
		))
		return i
	}
	fingerproxy.Run()
}

func fpJA3Raw(data *metadata.Metadata) (string, error) {
	hellobasic := &tlsx.ClientHelloBasic{}
	if err := hellobasic.Unmarshal(data.ClientHelloRecord); err != nil {
		return "", fmt.Errorf("ja3: %w", err)
	}

	fp := string(ja3.Bare(hellobasic))

	return fp, nil
}
