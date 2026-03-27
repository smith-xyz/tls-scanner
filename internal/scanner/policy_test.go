package scanner

import (
	"testing"
)

func TestPolicy(t *testing.T) {
	p := Policy()
	if p == nil {
		t.Fatal("Policy() returned nil")
	}
	if len(p.Rules) == 0 {
		t.Fatal("Policy() has no rules")
	}
}

func TestPolicyResolve(t *testing.T) {
	tests := []struct {
		name      string
		rules     []PolicyRule
		namespace string
		process   string
		component string
		port      int
		want      ComponentType
	}{
		{
			name:  "no rules = generic",
			rules: nil,
			port:  443,
			want:  GenericComponent,
		},
		{
			name:      "namespace match → ingress",
			rules:     []PolicyRule{{Namespace: "openshift-ingress", Profile: ProfileIngress}},
			namespace: "openshift-ingress",
			port:      443,
			want:      IngressComponent,
		},
		{
			name:      "namespace mismatch = generic",
			rules:     []PolicyRule{{Namespace: "openshift-ingress", Profile: ProfileIngress}},
			namespace: "openshift-kube-apiserver",
			port:      443,
			want:      GenericComponent,
		},
		{
			name:  "port match → kubelet",
			rules: []PolicyRule{{Port: intPtr(10250), Profile: ProfileKubelet}},
			port:  10250,
			want:  KubeletComponent,
		},
		{
			name:  "port mismatch = generic",
			rules: []PolicyRule{{Port: intPtr(10250), Profile: ProfileKubelet}},
			port:  443,
			want:  GenericComponent,
		},
		{
			name:    "process match → kubelet",
			rules:   []PolicyRule{{Process: "kubelet", Profile: ProfileKubelet}},
			process: "kubelet",
			port:    443,
			want:    KubeletComponent,
		},
		{
			name:      "component match → ingress",
			rules:     []PolicyRule{{Component: "router", Profile: ProfileIngress}},
			component: "router",
			port:      443,
			want:      IngressComponent,
		},
		{
			name: "first rule wins",
			rules: []PolicyRule{
				{Namespace: "openshift-ingress", Profile: ProfileIngress},
				{Port: intPtr(443), Profile: ProfileKubelet},
			},
			namespace: "openshift-ingress",
			port:      443,
			want:      IngressComponent,
		},
		{
			name: "multi-field AND: all match",
			rules: []PolicyRule{
				{Namespace: "openshift-ingress", Port: intPtr(443), Profile: ProfileIngress},
			},
			namespace: "openshift-ingress",
			port:      443,
			want:      IngressComponent,
		},
		{
			name: "multi-field AND: one field mismatches = no match",
			rules: []PolicyRule{
				{Namespace: "openshift-ingress", Port: intPtr(443), Profile: ProfileIngress},
			},
			namespace: "openshift-ingress",
			port:      8443,
			want:      GenericComponent,
		},
		{
			name:  "apiserver profile rule → generic component",
			rules: []PolicyRule{{Port: intPtr(6443), Profile: ProfileAPIServer}},
			port:  6443,
			want:  GenericComponent,
		},
		{
			name:  "empty rule (all wildcards) matches everything",
			rules: []PolicyRule{{Profile: ProfileKubelet}},
			port:  1234,
			want:  KubeletComponent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &ComponentPolicy{Rules: tt.rules}
			got := policy.Resolve(tt.namespace, tt.process, tt.component, tt.port)
			if got != tt.want {
				t.Errorf("Resolve(%q, %q, %q, %d) = %v, want %v",
					tt.namespace, tt.process, tt.component, tt.port, got, tt.want)
			}
		})
	}
}

func TestPolicyBehaviour(t *testing.T) {
	p := Policy()

	tests := []struct {
		name      string
		namespace string
		port      int
		want      ComponentType
	}{
		{"ingress namespace", "openshift-ingress", 443, IngressComponent},
		{"kubelet port 10250", "", 10250, KubeletComponent},
		{"kubelet port 10255", "", 10255, KubeletComponent},
		{"generic", "openshift-kube-apiserver", 6443, GenericComponent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.Resolve(tt.namespace, "", "", tt.port)
			if got != tt.want {
				t.Errorf("Policy().Resolve(%q, %d) = %v, want %v", tt.namespace, tt.port, got, tt.want)
			}
		})
	}
}

func intPtr(v int) *int { return &v }
