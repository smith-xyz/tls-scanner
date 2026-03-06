package scanner

import "log"

type PortFilter func(status ScanStatus) bool

var SkipUnscannable PortFilter = func(status ScanStatus) bool {
	return status == StatusNoPorts || status == StatusLocalhostOnly || status == StatusNoTLS
}

func PopulatePQCFields(pr *PortResult) {
	pr.TLS13Supported = stringInSlice("TLSv1.3", pr.TlsVersions)

	if pr.TlsKeyExchange == nil {
		return
	}

	if pr.TlsKeyExchange.ForwardSecrecy != nil {
		pr.MLKEMCiphers = pr.TlsKeyExchange.ForwardSecrecy.KEMs
		pr.MLKEMSupported = len(pr.MLKEMCiphers) > 0
	}

	seen := make(map[string]bool)
	for _, g := range pr.TlsKeyExchange.Groups {
		if !seen[g] {
			pr.AllKEMs = append(pr.AllKEMs, g)
			seen[g] = true
		}
	}
	if pr.TlsKeyExchange.ForwardSecrecy != nil {
		for _, k := range pr.TlsKeyExchange.ForwardSecrecy.KEMs {
			if !seen[k] {
				pr.AllKEMs = append(pr.AllKEMs, k)
				seen[k] = true
			}
		}
	}
}

func HasPQCComplianceFailures(results ScanResults, skip PortFilter) bool {
	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			if skip != nil && skip(portResult.Status) {
				continue
			}

			if !portResult.TLS13Supported {
				log.Printf("PQC compliance failure: %s:%d - TLS 1.3 not supported", ipResult.IP, portResult.Port)
				return true
			}

			if !portResult.MLKEMSupported {
				log.Printf("PQC compliance failure: %s:%d - ML-KEM not supported", ipResult.IP, portResult.Port)
				return true
			}

			hasValidMLKEM := false
			for _, kem := range portResult.MLKEMCiphers {
				if IsKEMGroup(kem) {
					hasValidMLKEM = true
					break
				}
			}
			if !hasValidMLKEM {
				log.Printf("PQC compliance failure: %s:%d - No valid ML-KEM KEM found", ipResult.IP, portResult.Port)
				return true
			}
		}
	}
	return false
}
