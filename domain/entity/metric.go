package entity

import (
	"fmt"
	"sync/atomic"
	"time"
)

// SSLRequestResult SSL request result structure
type SSLRequestResult struct {
	RequestTotal        int64         // Total number of requests
	RequestSuccessTotal int64         // Total number of successful requests
	RequestFailureTotal int64         // Total number of failed requests
	MaxCost             int64         // Maximum cost, in milliseconds
	MinCost             int64         // Minimum cost
	AverageCost         float64       // Average cost
	Counter             int64         // Counter for calculating QPS
	PreviousCounter     int64         // Previous counter
	PreTimer            time.Time     // Previous timer
	StartTimer          time.Time     // Start timer
	Elapsed             time.Duration // Duration
}

// NewSSLRequestResult New function to create an SSLRequestResult object
func NewSSLRequestResult() *SSLRequestResult {
	sslRequestResult := &SSLRequestResult{}
	sslRequestResult.RequestTotal = 0
	sslRequestResult.RequestSuccessTotal = 0
	sslRequestResult.RequestFailureTotal = 0
	sslRequestResult.MaxCost = 0
	sslRequestResult.MinCost = 0
	sslRequestResult.AverageCost = 0
	sslRequestResult.Counter = 0
	sslRequestResult.StartTimer = time.Now()
	sslRequestResult.PreTimer = time.Now()
	sslRequestResult.Elapsed = 0
	sslRequestResult.PreviousCounter = 0
	return sslRequestResult
}

// ToString Convert the structure to a string
func (s *SSLRequestResult) ToString() string {
	qps := s.GetQPS()
	avgQps, allElapsed := s.GetAllTheTimeQPS()
	format := "RequestTotal:%d RequestSuccessTotal:%d RequestFailureTotal:%d Elapsed:%0.2f MaxCost:%d MinCost:%d " +
		"AverageCost:%0.2f PreviousCounter:%d PreElapsed:%0.2f QPS:%.2f AVGQPS:%.2f"
	return fmt.Sprintf(
		format,
		s.RequestTotal,
		s.RequestSuccessTotal,
		s.RequestFailureTotal,
		allElapsed,
		s.MaxCost,
		s.MinCost,
		s.AverageCost,
		s.PreviousCounter,
		s.Elapsed.Seconds(),
		qps,
		avgQps,
	)
}

// GetQPS Calculate QPS
func (s *SSLRequestResult) GetQPS() float64 {
	s.Elapsed = time.Since(s.PreTimer)
	s.PreviousCounter = atomic.LoadInt64(&s.Counter)
	qps := float64(s.PreviousCounter) / s.Elapsed.Seconds()
	// 重置
	s.ResetQPS()
	return qps
}

// GetAllTheTimeQPS Calculate QPS algorithm for all the time
func (s *SSLRequestResult) GetAllTheTimeQPS() (float64, float64) {
	elapsed := time.Since(s.StartTimer)
	return float64(atomic.LoadInt64(&s.RequestTotal)) / elapsed.Seconds(), elapsed.Seconds()
}

// ResetQPS Reset QPS
func (s *SSLRequestResult) ResetQPS() {
	atomic.StoreInt64(&s.Counter, 0)
	s.PreTimer = time.Now()
}

// TotalAccount Add the total number of requests
func (s *SSLRequestResult) TotalAccount() {
	atomic.AddInt64(&s.RequestTotal, 1)
	atomic.AddInt64(&s.Counter, 1)
}

// TotalFailureAccount Add the total number of failed requests
func (s *SSLRequestResult) TotalFailureAccount() {
	atomic.AddInt64(&s.RequestFailureTotal, 1)
}

// TotalSuccessAccount Add the total number of successful requests
func (s *SSLRequestResult) TotalSuccessAccount() {
	atomic.AddInt64(&s.RequestSuccessTotal, 1)
}

// MaxCostCount Get the maximum cost
func (s *SSLRequestResult) MaxCostCount(currentCost int64) {
	if s.MaxCost < currentCost {
		s.MaxCost = currentCost
	}
}

// MinCostCount Get the minimum cost
func (s *SSLRequestResult) MinCostCount(currentCost int64) {
	if s.MinCost > currentCost {
		s.MinCost = currentCost
	}
}

// AverageCostCount Get the average cost
func (s *SSLRequestResult) AverageCostCount(currentCost int64) {
	if s.RequestTotal <= 1 {
		s.AverageCost = float64(currentCost)
	} else {
		s.AverageCost = (float64(s.RequestTotal-1)*s.AverageCost + float64(currentCost)) / float64(s.RequestTotal)
	}
}

// AllCostCount Unified calculation of duration
func (s *SSLRequestResult) AllCostCount(currentCost int64) {
	s.MaxCostCount(currentCost)
	s.MinCostCount(currentCost)
	s.AverageCostCount(currentCost)
}
