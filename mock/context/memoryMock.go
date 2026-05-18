package mock

import "errors"

// MemoryMock mocks the linear memory of a Wasmer instance and is used by the
// InstanceMock.
type MemoryMock struct {
	Pages    uint32
	PageSize uint32
	Contents []byte
}

// NewMemoryMock creates a new MemoryMock instance
func NewMemoryMock() *MemoryMock {
	memory := &MemoryMock{}
	memory.Pages = 2
	memory.PageSize = 65536
	memory.initMemory()
	return memory
}

// Length mocked method
func (memory *MemoryMock) Length() uint32 {
	return uint32(len(memory.Contents))
}

// Data mocked method
//
// Deprecated: use ReadMemory or WriteMemory. See issues/ISSUE-012.
func (memory *MemoryMock) Data() []byte {
	return memory.Contents
}

// ReadMemory returns a defensive copy of the requested range. Mirrors
// the wasmer.Memory.ReadMemory contract so the mock is interchangeable
// with the real wasmer memory in tests.
func (memory *MemoryMock) ReadMemory(offset uint32, length uint32) ([]byte, error) {
	end := uint64(offset) + uint64(length)
	if end > uint64(len(memory.Contents)) {
		return nil, errors.New("memory range out of bounds")
	}
	if length == 0 {
		return []byte{}, nil
	}
	out := make([]byte, length)
	copy(out, memory.Contents[offset:end])
	return out, nil
}

// WriteMemory copies data into mock memory at offset. No auto-grow,
// matching the wasmer.Memory.WriteMemory contract.
func (memory *MemoryMock) WriteMemory(offset uint32, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	end := uint64(offset) + uint64(len(data))
	if end > uint64(len(memory.Contents)) {
		return errors.New("memory range out of bounds")
	}
	copy(memory.Contents[offset:end], data)
	return nil
}

// Grow mocked method
func (memory *MemoryMock) Grow(pages uint32) error {
	newPages := make([]byte, pages*memory.PageSize)
	memory.Contents = append(memory.Contents, newPages...)
	return nil
}

// Destroy mocked method
func (memory *MemoryMock) Destroy() {
	memory.Contents = nil
}

// initMemory mocked method
func (memory *MemoryMock) initMemory() {
	memory.Contents = make([]byte, memory.Pages*memory.PageSize)
}

// IsInterfaceNil returns true if underlying object is nil
func (memory *MemoryMock) IsInterfaceNil() bool {
	return memory == nil
}
