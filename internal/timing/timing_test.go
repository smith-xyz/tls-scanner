package timing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrackRecordsEntry(t *testing.T) {
	t.Parallel()

	tc := &Collector{}
	stop := tc.Track("myFunc", "target1")
	time.Sleep(time.Millisecond)
	stop()

	tc.mu.Lock()
	defer tc.mu.Unlock()

	if len(tc.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(tc.entries))
	}
	e := tc.entries[0]
	if e.Function != "myFunc" {
		t.Errorf("Function = %q, want %q", e.Function, "myFunc")
	}
	if e.Target != "target1" {
		t.Errorf("Target = %q, want %q", e.Target, "target1")
	}
	if e.Duration < time.Millisecond {
		t.Errorf("Duration = %v, expected >= 1ms", e.Duration)
	}
}

func TestTrackMultipleEntries(t *testing.T) {
	t.Parallel()

	tc := &Collector{}
	stop1 := tc.Track("funcA", "")
	stop2 := tc.Track("funcB", "")
	stop1()
	stop2()

	tc.mu.Lock()
	defer tc.mu.Unlock()

	if len(tc.entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(tc.entries))
	}
}

func TestWriteReportEmpty(t *testing.T) {
	t.Parallel()

	tc := &Collector{}
	path := filepath.Join(t.TempDir(), "report.txt")

	if err := tc.WriteReport(path); err != nil {
		t.Fatalf("WriteReport returned error: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected no file for empty entries")
	}
}

func TestWriteReportContent(t *testing.T) {
	t.Parallel()

	tc := &Collector{}

	now := time.Now()
	tc.entries = []Entry{
		{Function: "scan", Target: "host1", Duration: 100 * time.Millisecond, Start: now.Add(10 * time.Millisecond)},
		{Function: "scan", Target: "host2", Duration: 200 * time.Millisecond, Start: now},
		{Function: "discover", Target: "", Duration: 50 * time.Millisecond, Start: now.Add(5 * time.Millisecond)},
	}

	path := filepath.Join(t.TempDir(), "sub", "report.txt")
	if err := tc.WriteReport(path); err != nil {
		t.Fatalf("WriteReport returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	content := string(data)

	// Entries should be sorted by start time: host2 (now), discover (now+5ms), host1 (now+10ms)
	idx2 := strings.Index(content, "host2")
	idxD := strings.Index(content, "discover")
	idx1 := strings.Index(content, "host1")
	if idx2 > idxD || idxD > idx1 {
		t.Error("entries not sorted by start time")
	}

	// Summary section should contain aggregation
	if !strings.Contains(content, "CALLS") {
		t.Error("missing summary header")
	}
	// scan should show 2 calls
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "scan") && strings.Contains(line, "2") {
			return
		}
	}
	t.Error("summary should show 2 calls for 'scan'")
}

func TestWriteReportCreatesDirectory(t *testing.T) {
	t.Parallel()

	tc := &Collector{}
	tc.entries = []Entry{
		{Function: "f", Target: "", Duration: time.Millisecond, Start: time.Now()},
	}

	path := filepath.Join(t.TempDir(), "deep", "nested", "report.txt")
	if err := tc.WriteReport(path); err != nil {
		t.Fatalf("WriteReport returned error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file at %s: %v", path, err)
	}
}
