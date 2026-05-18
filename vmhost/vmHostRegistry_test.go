package vmhost

import (
	"sync"
	"testing"
)

// vmHostStubForTest satisfies the VMHost interface by embedding it
// (interface embedding promotes all methods). The embedded VMHost is
// the zero value (nil), so any method call on this stub would panic
// — but the registry tests never invoke methods on the round-tripped
// interface; they only verify Register / Lookup / Release mechanics.
type vmHostStubForTest struct {
	VMHost
}

func newHostStub() VMHost {
	return &vmHostStubForTest{}
}

func TestVMHostRegistry_RegisterLookup(t *testing.T) {
	t.Parallel()

	r := &vmHostRegistry{entries: make(map[uint64]VMHost)}
	h := newHostStub()
	id := r.Register(h)
	if id == 0 {
		t.Fatal("expected non-zero handle")
	}
	got := r.Lookup(id)
	if got == nil {
		t.Fatal("Lookup returned nil for a freshly-registered handle")
	}
}

func TestVMHostRegistry_ReleaseStaleHandleReturnsNil(t *testing.T) {
	t.Parallel()

	r := &vmHostRegistry{entries: make(map[uint64]VMHost)}
	id := r.Register(newHostStub())
	r.Release(id)
	if got := r.Lookup(id); got != nil {
		t.Fatalf("Lookup of released handle returned %v, want nil", got)
	}
}

func TestVMHostRegistry_DoubleReleaseIsNoOp(t *testing.T) {
	t.Parallel()

	r := &vmHostRegistry{entries: make(map[uint64]VMHost)}
	id := r.Register(newHostStub())
	r.Release(id)
	// Must not panic; map.delete on a missing key is a no-op.
	r.Release(id)
	r.Release(id)
}

func TestVMHostRegistry_HandlesNeverReused(t *testing.T) {
	t.Parallel()

	r := &vmHostRegistry{entries: make(map[uint64]VMHost)}
	first := r.Register(newHostStub())
	r.Release(first)
	second := r.Register(newHostStub())
	if second <= first {
		t.Fatalf("expected monotonically increasing handles; got first=%d second=%d", first, second)
	}
}

// TestVMHostRegistry_ConcurrentRegisterLookupRelease — exercises the
// RWMutex under load. Run with `go test -race`.
func TestVMHostRegistry_ConcurrentRegisterLookupRelease(t *testing.T) {
	t.Parallel()

	r := &vmHostRegistry{entries: make(map[uint64]VMHost)}

	const goroutines = 32
	const opsPerGoroutine = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				id := r.Register(newHostStub())
				_ = r.Lookup(id)
				r.Release(id)
			}
		}()
	}
	wg.Wait()

	// After all goroutines finish, all handles released; the map
	// should be empty.
	r.mu.RLock()
	remaining := len(r.entries)
	r.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("registry leaked %d entries after symmetric register/release", remaining)
	}
}

// TestLookupVMHostOrPanic_PanicsOnMissingHandle confirms the
// "fail-loud" boundary in GetVMHost.
func TestLookupVMHostOrPanic_PanicsOnMissingHandle(t *testing.T) {
	t.Parallel()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for missing handle, got none")
		}
	}()
	// Use a handle value that is guaranteed not to exist in the global
	// registry — the registry uses an atomic monotonic counter starting
	// from 1, so 1 << 63 is safely beyond any plausible live handle.
	lookupVMHostOrPanic(uint64(1) << 63)
}

// TestUint64ToDecimalString_Roundtrip — covers the alloc-free
// formatter used in the panic message.
func TestUint64ToDecimalString_Roundtrip(t *testing.T) {
	t.Parallel()

	cases := []uint64{0, 1, 9, 10, 99, 100, 12345, 1<<63 - 1, 1 << 63}
	for _, v := range cases {
		got := uint64ToDecimalString(v)
		if got == "" {
			t.Fatalf("uint64ToDecimalString(%d) returned empty string", v)
		}
	}
}
