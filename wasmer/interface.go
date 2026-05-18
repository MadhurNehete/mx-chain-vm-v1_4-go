package wasmer

// InstanceHandler defines the functionality of a Wasmer instance
type InstanceHandler interface {
	HasMemory() bool
	HasFunction(funcName string) bool
	CallFunction(funcName string) (Value, error)
	SetContextData(data uintptr)
	GetPointsUsed() uint64
	SetPointsUsed(points uint64)
	SetGasLimit(gasLimit uint64)
	SetBreakpointValue(value uint64)
	GetBreakpointValue() uint64
	Cache() ([]byte, error)
	Clean() bool
	AlreadyCleaned() bool
	GetExports() ExportsMap
	GetSignature(functionName string) (*ExportedFunctionSignature, bool)
	GetData() uintptr
	GetInstanceCtxMemory() MemoryHandler
	GetMemory() MemoryHandler
	SetMemory(data []byte) bool
	IsFunctionImported(name string) bool
	IsInterfaceNil() bool
	Reset() bool
	ID() string
}

// MemoryHandler defines the functionality of the memory of a Wasmer instance.
//
// Data() is preserved for API compatibility but DEPRECATED — see
// issues/ISSUE-012. Production callers must use ReadMemory / WriteMemory
// which encapsulate the bounds-check + defensive-copy pattern and never
// expose the wasm-linear-memory alias to client code (so a slice held
// across a memory.Grow can never produce a UAF).
type MemoryHandler interface {
	Length() uint32
	// Deprecated: use ReadMemory or WriteMemory. See issues/ISSUE-012.
	Data() []byte
	// ReadMemory returns a defensive copy of the requested wasm memory
	// range. The returned slice is owned by Go and remains valid across
	// subsequent Grow calls.
	ReadMemory(offset uint32, length uint32) ([]byte, error)
	// WriteMemory copies `data` into wasm memory starting at `offset`.
	// Returns an error if the range doesn't fit in the current memory
	// size (does NOT auto-grow — the caller decides growth policy).
	WriteMemory(offset uint32, data []byte) error
	Grow(pages uint32) error
	Destroy()
	IsInterfaceNil() bool
}
