package fingerprint

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/0x4D31/fingerproxy/pkg/metadata"
)

func hexToBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const tlsHelloHex = "160301020b0100020703037f020a187f3aa7329f24155b77abff130dd616e200f6ef7d6c2d4657bf48218a20d945e74ab5e723901b3948e36cd39e248009489982497543815cdd74c3da32620076130213031301c02fc02bc030c02c009ec0270067c028006b00a3009fcca9cca8ccaac0afc0adc0a3c09fc05dc061c057c05300a2c0aec0acc0a2c09ec05cc060c056c052c024006ac0230040c00ac01400390038c009c01300330032009dc0a1c09dc051009cc0a0c09cc050003d003c0035002f00ff010001480000001b0019000016736869627579612e6170692e7375627363616e2e696f000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b00050403040303002d00020101003300260024001d00207289331a6f55556a98dfe0c96d52fc31d897644a5f87c3d71506b98fc198602300290094006f0069eb56145bbba79db5b290bd16a6133dea5d88e79857b13f7ac21c07962ca58afc84c0f1e8f29205c345c5eeeb67237ace5f6838feadfd2acadc5e464ddf7c9b3a9560d9dd6a8f030c452d6ea621b45e5c07e899184648adcc8a5d898ff6dc6050627de2070b9cd0efcea059033500212061b4238d30f5cda4b6559bd1061936b2912bd69a8b49610246db2d7bbae4b73c"
const quicHelloHex = "1603010077010000730303a4b9f667f45a582a22e99360a97e87de5d3e2cbfe9a524b16ba423473d0a8a1d20e66b3ad64af1bf659ef90b50353f446932b385955ceddeee672ca7e820de025a0026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a1301130213030100000400390000"

func TestJA4FingerprintTLSPrefix(t *testing.T) {
	data := &metadata.Metadata{ClientHelloRecord: hexToBytes(t, tlsHelloHex)}
	fp, err := JA4Fingerprint(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fp, "t") {
		t.Fatalf("expected prefix t, got %s", fp)
	}
}

func TestJA4FingerprintQUICPrefix(t *testing.T) {
	data := &metadata.Metadata{ClientHelloRecord: hexToBytes(t, quicHelloHex), IsQUIC: true}
	fp, err := JA4Fingerprint(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fp, "q") {
		t.Fatalf("expected prefix q, got %s", fp)
	}
}
