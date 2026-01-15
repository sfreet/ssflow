package main

import (
	"testing"
)

func TestIpToUint32(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		expected uint32
	}{
		{"ValidIP", "192.168.1.1", 3232235777},
		{"AnotherValidIP", "10.0.0.1", 167772161},
		{"InvalidIP", "not-an-ip", 0},
		{"EmptyIP", "", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ipToUint32(tc.ip)
			if result != tc.expected {
				t.Errorf("ipToUint32(%s) = %d; want %d", tc.ip, result, tc.expected)
			}
		})
	}
}
