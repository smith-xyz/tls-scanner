package k8s

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

const procStateListen = "0A"

func DiscoverPortsFromPodSpec(pod *v1.Pod) ([]int, error) {
	log.Printf("Discovering ports for pod %s/%s from API server...", pod.Namespace, pod.Name)

	var ports []int
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Protocol == v1.ProtocolTCP {
				ports = append(ports, int(port.ContainerPort))
			}
		}
	}

	for _, container := range pod.Spec.InitContainers {
		for _, port := range container.Ports {
			if port.Protocol == v1.ProtocolTCP {
				ports = append(ports, int(port.ContainerPort))
			}
		}
	}

	if len(ports) == 0 {
		log.Printf("Found 0 declared TCP ports for pod %s/%s.", pod.Namespace, pod.Name)
	} else {
		log.Printf("Found %d declared TCP ports for pod %s/%s: %v", len(ports), pod.Namespace, pod.Name, ports)
	}

	return ports, nil
}

func (c *Client) DiscoverPortsFromProc(pod PodInfo) ([]int, error) {
	if len(pod.Containers) == 0 {
		return nil, fmt.Errorf("pod %s/%s has no containers", pod.Namespace, pod.Name)
	}

	command := []string{"/bin/sh", "-c", "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null"}
	containerName := pod.Containers[0]

	req := c.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec")

	req.VersionedParams(&v1.PodExecOptions{
		Container: containerName,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(c.restCfg, "POST", req.URL())
	if err != nil {
		return nil, fmt.Errorf("failed to create executor for pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("/proc/net/tcp exec TIMED OUT in pod %s/%s (30s)", pod.Namespace, pod.Name)
		}
		return nil, fmt.Errorf("exec cat /proc/net/tcp in pod %s/%s failed: %w", pod.Namespace, pod.Name, err)
	}

	ports := ParseProcNetTCP(stdout.String())
	log.Printf("Discovered %d listening ports from /proc/net/tcp in pod %s/%s: %v", len(ports), pod.Namespace, pod.Name, ports)
	return ports, nil
}

func ParseProcNetTCP(output string) []int {
	seen := make(map[int]struct{})
	var ports []int

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		state := fields[3]
		if state != procStateListen {
			continue
		}

		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		port64, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}
		port := int(port64)

		if _, ok := seen[port]; !ok {
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}

	return ports
}

func UnionPorts(a, b []int) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	var result []int
	for _, p := range a {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			result = append(result, p)
		}
	}
	for _, p := range b {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			result = append(result, p)
		}
	}
	return result
}
