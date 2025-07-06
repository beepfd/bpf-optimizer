package main

import (
	"fmt"
	"strconv"
	"strings"
)

func isMaskPattern(hexStr string) bool {
	val, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return false
	}

	binStr := fmt.Sprintf("%032b", val)
	fmt.Printf("Testing %s -> %d -> %s\n", hexStr, val, binStr)

	// Check for monotonically decreasing pattern (from most significant bit)
	// A mask pattern typically has all 1s followed by all 0s (or similar patterns)
	inZeros := false
	for i := 0; i < len(binStr); i++ {
		if binStr[i] == '0' {
			inZeros = true
		} else if inZeros && binStr[i] == '1' {
			// Found a 1 after we've seen zeros - not a valid mask pattern
			fmt.Printf("  Failed: found 1 after 0 at position %d\n", i)
			return false
		}
	}

	hasOne := strings.Contains(binStr, "1")
	fmt.Printf("  Has 1s: %t\n", hasOne)
	return hasOne
}

func main() {
	tests := []string{"ffffffff", "ffff0000", "00000000", "12345678"}
	for _, test := range tests {
		result := isMaskPattern(test)
		fmt.Printf("isMaskPattern(%s) = %t\n\n", test, result)
	}
}