package k8s

import (
	"testing"
)

// newTestClient returns a Client with all internal maps initialised, suitable
// for unit tests that don't need a real Kubernetes API server.
func newTestClient() *Client {
	return &Client{
		processNameMap:            make(map[string]map[int]string),
		listenInfoMap:             make(map[string]map[int]ListenInfo),
		procListenAddrMap:         make(map[string]map[int]string),
		processDiscoveryAttempted: make(map[string]bool),
	}
}

func TestIsLocalhostOnly_lsofData(t *testing.T) {
	c := newTestClient()

	// Populate listenInfoMap as lsof would.
	c.listenInfoMap["10.0.0.1"] = map[int]ListenInfo{
		9259: {Port: 9259, ListenAddress: "127.0.0.1", ProcessName: "myprocess"},
		9258: {Port: 9258, ListenAddress: "*", ProcessName: "myprocess"},
	}

	tests := []struct {
		port     int
		wantIs   bool
		wantAddr string
	}{
		{9259, true, "127.0.0.1"}, // localhost in lsof data
		{9258, false, ""},         // wildcard in lsof data
		{9999, false, ""},         // unknown port
	}

	for _, tt := range tests {
		gotIs, gotAddr := c.IsLocalhostOnly("10.0.0.1", tt.port)
		if gotIs != tt.wantIs || gotAddr != tt.wantAddr {
			t.Errorf("IsLocalhostOnly(port=%d) = (%v, %q), want (%v, %q)",
				tt.port, gotIs, gotAddr, tt.wantIs, tt.wantAddr)
		}
	}
}

func TestIsLocalhostOnly_procFallback(t *testing.T) {
	c := newTestClient()

	// No lsof data at all (secondary container scenario).
	// Proc data covers all sockets via shared network namespace.
	c.procListenAddrMap["10.0.0.1"] = map[int]string{
		9260: "127.0.0.1", // secondary container's localhost port
		9261: "0.0.0.0",   // secondary container's wildcard port
	}

	tests := []struct {
		port     int
		wantIs   bool
		wantAddr string
	}{
		{9260, true, "127.0.0.1"}, // localhost via proc fallback
		{9261, false, ""},         // wildcard — not localhost
		{9999, false, ""},         // unknown
	}

	for _, tt := range tests {
		gotIs, gotAddr := c.IsLocalhostOnly("10.0.0.1", tt.port)
		if gotIs != tt.wantIs || gotAddr != tt.wantAddr {
			t.Errorf("IsLocalhostOnly(port=%d) = (%v, %q), want (%v, %q)",
				tt.port, gotIs, gotAddr, tt.wantIs, tt.wantAddr)
		}
	}
}

func TestIsLocalhostOnly_lsofTakesPrecedence(t *testing.T) {
	c := newTestClient()

	// lsof says port 9000 is wildcard; proc says it is localhost.
	// lsof should win (it has richer context from the process perspective).
	c.listenInfoMap["10.0.0.1"] = map[int]ListenInfo{
		9000: {Port: 9000, ListenAddress: "*", ProcessName: "svc"},
	}
	c.procListenAddrMap["10.0.0.1"] = map[int]string{
		9000: "127.0.0.1",
	}

	gotIs, _ := c.IsLocalhostOnly("10.0.0.1", 9000)
	if gotIs {
		t.Error("expected IsLocalhostOnly=false when lsof shows wildcard, even if proc shows localhost")
	}
}

func TestIsLocalhostOnly_ipv6Localhost(t *testing.T) {
	c := newTestClient()

	c.procListenAddrMap["10.0.0.2"] = map[int]string{
		8080: "::1",
	}

	gotIs, gotAddr := c.IsLocalhostOnly("10.0.0.2", 8080)
	if !gotIs || gotAddr != "::1" {
		t.Errorf("IsLocalhostOnly() = (%v, %q), want (true, %q)", gotIs, gotAddr, "::1")
	}
}

func TestGetListenInfo(t *testing.T) {
	t.Parallel()

	c := newTestClient()
	c.listenInfoMap["10.0.0.1"] = map[int]ListenInfo{
		443: {Port: 443, ListenAddress: "0.0.0.0", ProcessName: "nginx"},
	}

	info, ok := c.GetListenInfo("10.0.0.1", 443)
	if !ok {
		t.Fatal("expected ok=true for known port")
	}
	if info.ListenAddress != "0.0.0.0" {
		t.Errorf("ListenAddress = %q, want %q", info.ListenAddress, "0.0.0.0")
	}

	_, ok = c.GetListenInfo("10.0.0.1", 9999)
	if ok {
		t.Error("expected ok=false for unknown port")
	}

	_, ok = c.GetListenInfo("10.0.0.2", 443)
	if ok {
		t.Error("expected ok=false for unknown IP")
	}
}

func TestGetProcessName(t *testing.T) {
	t.Parallel()

	c := newTestClient()
	c.processNameMap["10.0.0.1"] = map[int]string{
		443: "nginx",
	}

	name, ok := c.GetProcessName("10.0.0.1", 443)
	if !ok || name != "nginx" {
		t.Errorf("GetProcessName() = (%q, %v), want (%q, true)", name, ok, "nginx")
	}

	_, ok = c.GetProcessName("10.0.0.1", 9999)
	if ok {
		t.Error("expected ok=false for unknown port")
	}

	_, ok = c.GetProcessName("10.0.0.2", 443)
	if ok {
		t.Error("expected ok=false for unknown IP")
	}
}

func TestParseLsofOutput(t *testing.T) {
	tests := []struct {
		name          string
		output        string
		ips           []string
		wantProcesses map[string]map[int]string
		wantListen    map[string]map[int]ListenInfo
	}{
		{
			name:   "ipv4 wildcard",
			output: "p1\ncmyproc\nn*:9099\n",
			ips:    []string{"10.0.0.1"},
			wantProcesses: map[string]map[int]string{
				"10.0.0.1": {9099: "myproc"},
			},
			wantListen: map[string]map[int]ListenInfo{
				"10.0.0.1": {9099: {Port: 9099, ListenAddress: "*", ProcessName: "myproc"}},
			},
		},
		{
			name:   "ipv4 localhost",
			output: "p1\ncmyproc\nn127.0.0.1:8080\n",
			ips:    []string{"10.0.0.1"},
			wantProcesses: map[string]map[int]string{
				"10.0.0.1": {8080: "myproc"},
			},
			wantListen: map[string]map[int]ListenInfo{
				"10.0.0.1": {8080: {Port: 8080, ListenAddress: "127.0.0.1", ProcessName: "myproc"}},
			},
		},
		{
			name:   "ipv6 wildcard bracket notation",
			output: "p1\nckube-rbac\nn[::]:8443\n",
			ips:    []string{"10.0.0.1"},
			wantProcesses: map[string]map[int]string{
				"10.0.0.1": {8443: "kube-rbac"},
			},
			wantListen: map[string]map[int]ListenInfo{
				"10.0.0.1": {8443: {Port: 8443, ListenAddress: "::", ProcessName: "kube-rbac"}},
			},
		},
		{
			name:   "ipv6 localhost bracket notation",
			output: "p1\ncmetrics\nn[::1]:9090\n",
			ips:    []string{"10.0.0.1"},
			wantProcesses: map[string]map[int]string{
				"10.0.0.1": {9090: "metrics"},
			},
			wantListen: map[string]map[int]ListenInfo{
				"10.0.0.1": {9090: {Port: 9090, ListenAddress: "::1", ProcessName: "metrics"}},
			},
		},
		{
			name:   "mixed ipv4 and ipv6",
			output: "p1\ncmain\nn*:9091\np2\nckube-rbac\nn[::]:8443\n",
			ips:    []string{"10.0.0.1"},
			wantProcesses: map[string]map[int]string{
				"10.0.0.1": {9091: "main", 8443: "kube-rbac"},
			},
			wantListen: map[string]map[int]ListenInfo{
				"10.0.0.1": {
					9091: {Port: 9091, ListenAddress: "*", ProcessName: "main"},
					8443: {Port: 8443, ListenAddress: "::", ProcessName: "kube-rbac"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProc, gotListen := ParseLsofOutput(tt.output, tt.ips, "test-ns", "test-pod")
			for ip, wantPorts := range tt.wantProcesses {
				for port, wantName := range wantPorts {
					if gotProc[ip][port] != wantName {
						t.Errorf("processMap[%s][%d] = %q, want %q", ip, port, gotProc[ip][port], wantName)
					}
				}
			}
			for ip, wantPorts := range tt.wantListen {
				for port, wantInfo := range wantPorts {
					gotInfo, ok := gotListen[ip][port]
					if !ok {
						t.Errorf("listenInfoMap missing ip=%s port=%d", ip, port)
						continue
					}
					if gotInfo != wantInfo {
						t.Errorf("listenInfoMap[%s][%d] = %+v, want %+v", ip, port, gotInfo, wantInfo)
					}
				}
			}
		})
	}
}

func TestIsLocalhostAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"localhost", true},
		{"0.0.0.0", false},
		{"::", false},
		{"*", false},
		{"10.0.0.1", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isLocalhostAddr(tt.addr)
		if got != tt.want {
			t.Errorf("isLocalhostAddr(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
