package scanner

import (
	"github.com/openshift/tls-scanner/internal/k8s"
)

func getMinVersionValue(versions []string) int {
	if len(versions) == 0 {
		return 0
	}
	minVersion := TLSVersionValueMap[versions[0]]
	for _, v := range versions[1:] {
		verVal := TLSVersionValueMap[v]
		if verVal < minVersion {
			minVersion = verVal
		}
	}
	return minVersion
}

func CheckCompliance(portResult *PortResult, tlsProfile *k8s.TLSSecurityProfile) {
	portResultMinVersion := 0
	if portResult.TlsVersions != nil {
		portResultMinVersion = getMinVersionValue(portResult.TlsVersions)
	}

	portResult.IngressTLSConfigCompliance = &TLSConfigComplianceResult{}
	portResult.APIServerTLSConfigCompliance = &TLSConfigComplianceResult{}
	portResult.KubeletTLSConfigCompliance = &TLSConfigComplianceResult{}

	if ingress := tlsProfile.IngressController; tlsProfile.IngressController != nil {
		if ingress.MinTLSVersion != "" {
			ingressMinVersion := TLSVersionValueMap[ingress.MinTLSVersion]
			portResult.IngressTLSConfigCompliance.Version = (portResultMinVersion >= ingressMinVersion)
		}
		portResult.IngressTLSConfigCompliance.Ciphers = checkCipherCompliance(portResult.TlsCiphers, ingress.Ciphers)
	}

	if api := tlsProfile.APIServer; tlsProfile.APIServer != nil {
		if api.MinTLSVersion != "" {
			apiMinVersion := TLSVersionValueMap[api.MinTLSVersion]
			portResult.APIServerTLSConfigCompliance.Version = (portResultMinVersion >= apiMinVersion)
		}
		portResult.APIServerTLSConfigCompliance.Ciphers = checkCipherCompliance(portResult.TlsCiphers, api.Ciphers)
	}

	if kube := tlsProfile.KubeletConfig; tlsProfile.KubeletConfig != nil {
		if kube.MinTLSVersion != "" {
			kubMinVersion := TLSVersionValueMap[kube.MinTLSVersion]
			portResult.KubeletTLSConfigCompliance.Version = (portResultMinVersion >= kubMinVersion)
		}
		portResult.KubeletTLSConfigCompliance.Ciphers = checkCipherCompliance(portResult.TlsCiphers, kube.TLSCipherSuites)
	}
}

func checkCipherCompliance(gotCiphers []string, expectedCiphers []string) bool {
	expectedSet := make(map[string]struct{}, len(expectedCiphers))
	for _, c := range expectedCiphers {
		expectedSet[c] = struct{}{}
	}

	if len(gotCiphers) == 0 && len(expectedCiphers) > 0 {
		return false
	}

	for _, cipher := range gotCiphers {
		convertedCipher := IanaCipherToOpenSSLCipherMap[cipher]
		if _, exists := expectedSet[convertedCipher]; !exists {
			return false
		}
	}

	return true
}

func HasComplianceFailures(results ScanResults) bool {
	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			if portResult.IngressTLSConfigCompliance != nil &&
				(!portResult.IngressTLSConfigCompliance.Version || !portResult.IngressTLSConfigCompliance.Ciphers) {
				return true
			}
			if portResult.APIServerTLSConfigCompliance != nil &&
				(!portResult.APIServerTLSConfigCompliance.Version || !portResult.APIServerTLSConfigCompliance.Ciphers) {
				return true
			}
			if portResult.KubeletTLSConfigCompliance != nil &&
				(!portResult.KubeletTLSConfigCompliance.Version || !portResult.KubeletTLSConfigCompliance.Ciphers) {
				return true
			}
		}
	}
	return false
}
