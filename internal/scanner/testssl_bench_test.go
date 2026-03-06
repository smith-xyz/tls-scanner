package scanner

import (
	"os"
	"testing"
)

var (
	singleFixture []byte
	batchFixture  []byte
)

func init() {
	var err error
	singleFixture, err = os.ReadFile("../testdata/testssl_single.json")
	if err != nil {
		panic("missing testdata/testssl_single.json: " + err.Error())
	}
	batchFixture, err = os.ReadFile("../testdata/testssl_batch.json")
	if err != nil {
		panic("missing testdata/testssl_batch.json: " + err.Error())
	}
}

func BenchmarkParseTestSSLOutput(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ParseTestSSLOutput(singleFixture, "10.128.0.15", "8443")
	}
}

func BenchmarkGroupTestSSLOutputByIPPort(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = GroupTestSSLOutputByIPPort(batchFixture)
	}
}

func BenchmarkExtractKeyExchangeFromTestSSL(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ExtractKeyExchangeFromTestSSL(singleFixture)
	}
}

func BenchmarkExtractTLSInfo(b *testing.B) {
	scanRun := ParseTestSSLOutput(singleFixture, "10.128.0.15", "8443")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ExtractTLSInfo(scanRun)
	}
}
