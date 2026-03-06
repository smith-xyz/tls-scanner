package k8s

import "testing"

func makePods(namespaces ...string) []PodInfo {
	var pods []PodInfo
	for _, ns := range namespaces {
		pods = append(pods, PodInfo{Name: "pod-" + ns, Namespace: ns, IPs: []string{"10.0.0.1"}})
	}
	return pods
}

func TestFilterPodsByNamespace(t *testing.T) {
	pods := makePods("openshift-apiserver", "openshift-etcd", "kube-system", "default")

	filtered := FilterPodsByNamespace(pods, "openshift-apiserver")
	if len(filtered) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(filtered))
	}
	if filtered[0].Namespace != "openshift-apiserver" {
		t.Errorf("expected namespace openshift-apiserver, got %s", filtered[0].Namespace)
	}
}

func TestFilterPodsByNamespaceMultiple(t *testing.T) {
	pods := makePods("openshift-apiserver", "openshift-etcd", "kube-system", "default")

	filtered := FilterPodsByNamespace(pods, "openshift-apiserver,openshift-etcd")
	if len(filtered) != 2 {
		t.Fatalf("expected 2 pods, got %d", len(filtered))
	}

	ns := map[string]bool{}
	for _, p := range filtered {
		ns[p.Namespace] = true
	}
	if !ns["openshift-apiserver"] || !ns["openshift-etcd"] {
		t.Errorf("expected apiserver and etcd, got %v", ns)
	}
}

func TestFilterPodsByNamespaceEmpty(t *testing.T) {
	pods := makePods("openshift-apiserver", "openshift-etcd")

	filtered := FilterPodsByNamespace(pods, "")
	if len(filtered) != len(pods) {
		t.Errorf("empty filter should return all pods: expected %d, got %d", len(pods), len(filtered))
	}
}

func TestFilterPodsByNamespaceNoMatch(t *testing.T) {
	pods := makePods("openshift-apiserver", "openshift-etcd")

	filtered := FilterPodsByNamespace(pods, "nonexistent-ns")
	if len(filtered) != 0 {
		t.Errorf("expected 0 pods for nonexistent namespace, got %d", len(filtered))
	}
}

func TestFilterPodsByNamespaceWhitespace(t *testing.T) {
	pods := makePods("openshift-apiserver", "openshift-etcd", "kube-system")

	filtered := FilterPodsByNamespace(pods, " openshift-apiserver , openshift-etcd ")
	if len(filtered) != 2 {
		t.Fatalf("expected 2 pods (whitespace should be trimmed), got %d", len(filtered))
	}
}
