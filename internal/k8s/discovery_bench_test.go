package k8s

import (
	"os"
	"testing"
)

var procNetTCPFixture string

func init() {
	data, err := os.ReadFile("../testdata/proc_net_tcp.txt")
	if err != nil {
		panic("missing testdata/proc_net_tcp.txt: " + err.Error())
	}
	procNetTCPFixture = string(data)
}

func BenchmarkParseProcNetTCP(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ParseProcNetTCP(procNetTCPFixture)
	}
}

func BenchmarkUnionPorts(b *testing.B) {
	a := []int{80, 443, 8443, 6443, 9090, 2379, 2380, 10250, 10257, 10259}
	extra := []int{8080, 3000, 5000, 443, 9443, 8444, 4001, 9090, 8443, 6443, 10250}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		UnionPorts(a, extra)
	}
}
