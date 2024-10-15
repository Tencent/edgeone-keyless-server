package entity

import (
	"sync/atomic"
)

// CertInfo holds the certificate information.
type CertInfo struct {
	// Certificate information is stored using the certificate file name (without extension) as the key
	HostKeyMap map[string]*CertificateInfo
	// Certificate information is stored using a combination of the certificate's SN and issuer as the key or just SN as
	// the key

	UniqKeyMap map[string]*CertificateInfo
}

// NewCertInfo creates a new certificate information
func NewCertInfo() *CertInfo {
	certInfo := &CertInfo{}
	certInfo.HostKeyMap = make(map[string]*CertificateInfo)
	certInfo.UniqKeyMap = make(map[string]*CertificateInfo)
	return certInfo
}

// LoadCertInfoData is the data structure for loading certificate information
type LoadCertInfoData struct {
	certInfo          CertInfo
	atomicBoolCurrent uint32 // Indicates whether it is currently in use
	DataLock          TimeoutRWMutex
}

// DeepCopy the certificate information of LoadCertInfoData
func (l *LoadCertInfoData) DeepCopy(src *LoadCertInfoData) {
	if l.certInfo.HostKeyMap == nil {
		l.certInfo.HostKeyMap = make(map[string]*CertificateInfo)
	}
	for k, v := range src.certInfo.HostKeyMap {
		ce := *v
		l.certInfo.HostKeyMap[k] = &ce
	}
	if l.certInfo.UniqKeyMap == nil {
		l.certInfo.UniqKeyMap = make(map[string]*CertificateInfo)
	}
	for k, v := range src.certInfo.UniqKeyMap {
		ce := *v
		l.certInfo.UniqKeyMap[k] = &ce
	}
}

// NewLoadCertInfoData creates a new LoadCertInfoData
func NewLoadCertInfoData() *LoadCertInfoData {
	loadCertInfoData := &LoadCertInfoData{}
	loadCertInfoData.certInfo = *NewCertInfo()
	loadCertInfoData.atomicBoolCurrent = 0
	return loadCertInfoData
}

// KeyLessCert Certificate information for OC authentication response
type KeyLessCert struct {
	CertInfoA LoadCertInfoData
	CertInfoB LoadCertInfoData
}

// NewKeyLessCert creates a new KeyLessCert
func NewKeyLessCert() *KeyLessCert {
	KeyLessCert := &KeyLessCert{}
	KeyLessCert.CertInfoA = *NewLoadCertInfoData()
	KeyLessCert.CertInfoB = *NewLoadCertInfoData()
	return KeyLessCert
}

// GetCurrentOne Get the current memory block
func (c *KeyLessCert) GetCurrentOne() *LoadCertInfoData {
	if c.CertInfoA.IsCurrent() {
		return &c.CertInfoA
	}
	return &c.CertInfoB
}

// GetUpdateOne Get the memory block to be updated
func (c *KeyLessCert) GetUpdateOne() *LoadCertInfoData {
	if c.CertInfoA.IsCurrent() {
		return &c.CertInfoB
	}
	return &c.CertInfoA
}

// SyncAB Synchronize the memory block to be updated with the current memory block
func (c *KeyLessCert) SyncAB() {
	if c.GetUpdateFlag() == "A" {
		c.CertInfoB.DeepCopy(&c.CertInfoA)
	} else {
		c.CertInfoA.DeepCopy(&c.CertInfoB)
	}
}

// GetUpdateFlag Get the memory block to be updated
func (c *KeyLessCert) GetUpdateFlag() string {
	if c.CertInfoA.IsCurrent() {
		return "B"
	}
	return "A"
}

// GetCurrentFlag Get the current memory block for reading
func (c *KeyLessCert) GetCurrentFlag() string {
	if c.CertInfoA.IsCurrent() {
		return "A"
	}
	return "B"
}

// SetCurrent Set the current memory block for reading
func (c *KeyLessCert) SetCurrent() {
	if c.CertInfoA.IsCurrent() {
		c.CertInfoB.SetCurrent(true)
		c.CertInfoA.SetCurrent(false)
	} else {
		c.CertInfoA.SetCurrent(true)
		c.CertInfoB.SetCurrent(false)
	}
}

// IsCurrent Check the atomicBoolCurrent
func (c *LoadCertInfoData) IsCurrent() bool {
	return atomic.LoadUint32(&c.atomicBoolCurrent) == 1
}

// SetCurrent Modify the atomicBoolCurrent
func (c *LoadCertInfoData) SetCurrent(isCurrent bool) {
	if isCurrent {
		atomic.StoreUint32(&c.atomicBoolCurrent, 1)
	} else {
		atomic.StoreUint32(&c.atomicBoolCurrent, 0)
	}
}

// GetCertInfo Get the certificate information in service
func (c *LoadCertInfoData) GetCertInfo() *CertInfo {
	return &c.certInfo
}

// CurrentCertInfoPtr Current certificate information in service
type CurrentCertInfoPtr struct {
	certInfo *CertInfo
	DataLock TimeoutRWMutex
}

// NewCurrentCertInfoPtr creates a new CurrentCertInfoPtr
func NewCurrentCertInfoPtr() *CurrentCertInfoPtr {
	currentCertInfoPtr := &CurrentCertInfoPtr{}
	currentCertInfoPtr.certInfo = nil
	return currentCertInfoPtr
}

// GetCertInfo Get the certificate information in service
func (c *CurrentCertInfoPtr) GetCertInfo() *CertInfo {
	return c.certInfo
}

// SetCertInof Set the certificate information in service
func (c *CurrentCertInfoPtr) SetCertInof(certInfo *CertInfo) {
	c.certInfo = certInfo
}
