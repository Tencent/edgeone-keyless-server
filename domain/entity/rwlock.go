package entity

import (
	"sync"
	"time"
)

const (
	TIME_WAIT_RW  = 5
	TIME_INTERVAL = 10 * time.Millisecond
)

// TimeoutRWMutex is a read/write mutex with a timeout.
type TimeoutRWMutex struct {
	sync.RWMutex
	lockCnt int32
}

// NewTimeoutRWMutex creates a new TimeoutRWMutex.
func NewTimeoutRWMutex() *TimeoutRWMutex {
	mutex := &TimeoutRWMutex{}
	mutex.lockCnt = 0
	return mutex
}

// TryRLockImmediately tries to acquire a read lock immediately.
func (m *TimeoutRWMutex) TryRLockImmediately() bool {
	return m.RWMutex.TryRLock()
}

// TryLockImmediately tries to acquire a write lock immediately.
func (m *TimeoutRWMutex) TryLockImmediately() bool {
	return m.RWMutex.TryLock()
}

// TryRLock tries to acquire a read lock with a timeout.
func (m *TimeoutRWMutex) TryRLock(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if m.RWMutex.TryRLock() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(TIME_INTERVAL)
	}
}

// Unlock unlocks the mutex.
func (m *TimeoutRWMutex) Unlock() {
	m.RWMutex.Unlock()
}

// RUnlock unlocks the mutex.
func (m *TimeoutRWMutex) RUnlock() {
	m.RWMutex.RUnlock()
}

// TryLock tries to acquire a write lock with a timeout.
func (m *TimeoutRWMutex) TryLock(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if m.RWMutex.TryLock() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(TIME_INTERVAL)
	}
}
