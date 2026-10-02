package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
)

const maxJobEvents = 512

type Step struct {
	Step   string `json:"step"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type Outcome struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Result any    `json:"result,omitempty"`
}

type Job struct {
	ID   string
	Kind string

	mu      sync.Mutex
	steps   []Step
	done    bool
	outcome Outcome
	wake    chan struct{}
}

func NewJob(kind string) *Job {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return &Job{ID: hex.EncodeToString(b), Kind: kind, wake: make(chan struct{})}
}

func (j *Job) signal() {
	close(j.wake)
	j.wake = make(chan struct{})
}

func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func (j *Job) Event(ev agentapi.Event) {
	if ev.Done {
		return
	}
	j.Add(Step{Step: ev.Step, Status: ev.Status, Detail: ev.Detail})
}

func (j *Job) Add(s Step) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.done || len(j.steps) >= maxJobEvents {
		return
	}
	s.Step = clean(s.Step, 80)
	s.Status = clean(s.Status, 16)
	s.Detail = clean(s.Detail, 400)
	j.steps = append(j.steps, s)
	j.signal()
}

func (j *Job) Finish(result any, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.done {
		return
	}
	j.done = true
	if err != nil {
		j.outcome = Outcome{OK: false, Error: clean(err.Error(), 400)}
	} else {
		j.outcome = Outcome{OK: true, Result: result}
	}
	j.signal()
}

func (j *Job) State() (steps []Step, done bool, out Outcome) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]Step(nil), j.steps...), j.done, j.outcome
}

func (j *Job) Running() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return !j.done
}

func (j *Job) Wait(timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		j.mu.Lock()
		if j.done {
			j.mu.Unlock()
			return true
		}
		ch := j.wake
		j.mu.Unlock()
		select {
		case <-ch:
		case <-deadline:
			return false
		}
	}
}

func (j *Job) resume(r *http.Request) int {
	last := r.Header.Get("Last-Event-ID")
	if last == "" {
		last = r.URL.Query().Get("last")
	}
	id, n, ok := strings.Cut(last, ".")
	if !ok || id != j.ID {
		return 0
	}
	v, err := strconv.Atoi(n)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

var Ping = 15 * time.Second

func (j *Job) ServeSSE(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		Error(w, http.StatusInternalServerError, "INTERNAL", "Streaming is not supported.")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	next := j.resume(r)
	fmt.Fprintf(w, "retry: 2000\n\n")
	fl.Flush()
	tick := time.NewTicker(Ping)
	defer tick.Stop()
	for {
		j.mu.Lock()
		steps := j.steps
		done := j.done
		out := j.outcome
		ch := j.wake
		j.mu.Unlock()
		if next > len(steps) {
			next = 0
		}
		for ; next < len(steps); next++ {
			b, _ := json.Marshal(steps[next])
			fmt.Fprintf(w, "id: %s.%d\nevent: step\ndata: %s\n\n", j.ID, next+1, b)
		}
		if done {
			b, _ := json.Marshal(out)
			fmt.Fprintf(w, "id: %s.%d\nevent: done\ndata: %s\n\n", j.ID, len(steps), b)
			fl.Flush()
			return
		}
		fl.Flush()
		select {
		case <-ch:
		case <-tick.C:
			fmt.Fprintf(w, "event: ping\ndata: {}\n\n")
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
