package fingerprint

import (
	"fmt"
	"net/http"
	"time"

	"github.com/0x4D31/fingerproxy/pkg/ja4h"
	"github.com/0x4D31/fingerproxy/pkg/metadata"
	"github.com/prometheus/client_golang/prometheus"
)

// JA4HFingerprintHeaderInjector injects the JA4H fingerprint into requests.
type JA4HFingerprintHeaderInjector struct {
	HeaderName                       string
	FingerprintDurationSucceedMetric prometheus.Observer
	FingerprintDurationErrorMetric   prometheus.Observer
}

// NewJA4HFingerprintHeaderInjector creates a header injector for JA4H.
func NewJA4HFingerprintHeaderInjector(headerName string) *JA4HFingerprintHeaderInjector {
	i := &JA4HFingerprintHeaderInjector{HeaderName: headerName}
	if fingerprintDurationMetric != nil {
		i.FingerprintDurationSucceedMetric = fingerprintDurationMetric.WithLabelValues("1", headerName)
		i.FingerprintDurationErrorMetric = fingerprintDurationMetric.WithLabelValues("0", headerName)
	}
	return i
}

func (i *JA4HFingerprintHeaderInjector) GetHeaderName() string {
	return i.HeaderName
}

func (i *JA4HFingerprintHeaderInjector) GetHeaderValue(req *http.Request) (string, error) {
	data, ok := metadata.FromContext(req.Context())
	if !ok {
		return "", fmt.Errorf("failed to get context")
	}

	ordered := data.OrderedHTTP1Headers
	if req.ProtoMajor == 2 {
		ordered = data.OrderedHTTP2Headers
	}

	start := time.Now()
	fp := ja4h.FromRequest(req, ordered)
	duration := time.Since(start)
	vlogf("fingerprint duration: %s", duration)

	if i.FingerprintDurationSucceedMetric != nil {
		i.FingerprintDurationSucceedMetric.Observe(duration.Seconds())
	}
	return fp, nil
}
