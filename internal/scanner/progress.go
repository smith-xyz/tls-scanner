package scanner

import (
	"fmt"
	"sync/atomic"
	"time"
)

type ProgressTracker struct {
	totalPods      int
	discoveredPods atomic.Int64
	queuedPorts    atomic.Int64
	skippedPorts   atomic.Int64
	startTime      time.Time
	done           chan struct{}
}

func NewProgressTracker(totalPods int) *ProgressTracker {
	return &ProgressTracker{
		totalPods: totalPods,
		startTime: time.Now(),
		done:      make(chan struct{}),
	}
}

func (p *ProgressTracker) Start(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.print()
			case <-p.done:
				return
			}
		}
	}()
}

func (p *ProgressTracker) Stop() {
	close(p.done)
}

func (p *ProgressTracker) print() {
	elapsed := time.Since(p.startTime).Truncate(time.Second)
	discovered := p.discoveredPods.Load()
	queued := p.queuedPorts.Load()
	skipped := p.skippedPorts.Load()

	fmt.Printf("[PROGRESS] %s | Discovery: %d/%d pods | Ports: %d queued, %d skipped\n",
		elapsed, discovered, p.totalPods, queued, skipped)
}

func (p *ProgressTracker) PodDiscovered() { p.discoveredPods.Add(1) }
func (p *ProgressTracker) PortQueued()    { p.queuedPorts.Add(1) }
func (p *ProgressTracker) PortSkipped()   { p.skippedPorts.Add(1) }
func (p *ProgressTracker) QueuedCount() int64 { return p.queuedPorts.Load() }
