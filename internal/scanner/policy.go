package scanner

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed policy.yaml
var embeddedPolicyYAML []byte

// ProfileSource names the TLS profile source that should be used when checking
// compliance for a matched component.
type ProfileSource string

const (
	ProfileAPIServer ProfileSource = "apiserver"
	ProfileIngress   ProfileSource = "ingress"
	ProfileKubelet   ProfileSource = "kubelet"
)

// PolicyRule matches a scanned port by any combination of namespace, process
// name, port number, and component name. Omitted fields act as wildcards.
// When all specified fields match, the first such rule wins and the port is
// checked against the given Profile.
type PolicyRule struct {
	Namespace string        `yaml:"namespace,omitempty"`
	Process   string        `yaml:"process,omitempty"`
	Port      *int          `yaml:"port,omitempty"`
	Component string        `yaml:"component,omitempty"`
	Profile   ProfileSource `yaml:"profile"`
}

// ComponentPolicy is a prioritised list of PolicyRules. Rules are evaluated
// top-to-bottom; the first matching rule wins. Ports with no matching rule are
// checked against the cluster-wide APIServer TLS profile.
//
// The active policy is defined in policy.yaml and embedded at build time.
// Changes to that file must go through the normal review process.
type ComponentPolicy struct {
	Rules []PolicyRule `yaml:"rules"`
}

// Policy returns the org-wide component policy embedded in the binary.
// It is the single source of truth for which TLS profile applies to each
// component type. To change the policy, edit policy.yaml and submit for review.
func Policy() *ComponentPolicy {
	var p ComponentPolicy
	if err := yaml.Unmarshal(embeddedPolicyYAML, &p); err != nil {
		// policy.yaml is checked into source; a parse failure is a programming error.
		panic(fmt.Sprintf("failed to parse embedded policy: %v", err))
	}
	return &p
}

// Resolve returns the ComponentType for a port with the given attributes by
// evaluating the policy rules in order. Returns GenericComponent if no rule
// matches.
func (p *ComponentPolicy) Resolve(namespace, process, component string, port int) ComponentType {
	for _, rule := range p.Rules {
		if rule.matches(namespace, process, component, port) {
			switch rule.Profile {
			case ProfileIngress:
				return IngressComponent
			case ProfileKubelet:
				return KubeletComponent
			default:
				return GenericComponent
			}
		}
	}
	return GenericComponent
}

func (r *PolicyRule) matches(namespace, process, component string, port int) bool {
	if r.Namespace != "" && r.Namespace != namespace {
		return false
	}
	if r.Process != "" && r.Process != process {
		return false
	}
	if r.Component != "" && r.Component != component {
		return false
	}
	if r.Port != nil && *r.Port != port {
		return false
	}
	return true
}
