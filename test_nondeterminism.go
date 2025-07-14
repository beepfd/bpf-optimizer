package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test_nondeterminism.go <num_runs>")
		return
	}

	numRuns, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("Invalid number: %s\n", os.Args[1])
		return
	}

	fmt.Printf("Running TestNewSection %d times to detect non-determinism...\n", numRuns)

	results := make(chan bool, numRuns)
	var wg sync.WaitGroup

	// Run tests in parallel
	for i := 0; i < numRuns; i++ {
		wg.Add(1)
		go func(runNum int) {
			defer wg.Done()

			// go test -timeout 30s -tags netgo,osusergo -run ^TestNewSection$ github.com/beepfd/bpf-optimizer/pkg/optimizer -v
			cmd := exec.Command("go", "test", "-count=1", "-timeout", "30s", "-tags", "netgo,osusergo", "-run", "^TestNewSection$", "github.com/beepfd/bpf-optimizer/pkg/optimizer", "-v")
			output, err := cmd.CombinedOutput()

			success := err == nil
			if !success {
				fmt.Printf("Run %d: FAILED\n", runNum)
				// Show debug output from first few failed runs for comparison
				if runNum < 3 {
					fmt.Printf("=== FAILED RUN %d DEBUG OUTPUT ===\n", runNum)
					fmt.Printf("%s\n", string(output))
					fmt.Printf("=== END FAILED RUN %d ===\n", runNum)
				}
			} else {
				fmt.Printf("Run %d: PASSED\n", runNum)
				// Save debug output from successful run
				fmt.Printf("=== SUCCESSFUL RUN %d DEBUG OUTPUT ===\n", runNum)
				fmt.Printf("%s\n", string(output))
				fmt.Printf("=== END SUCCESSFUL RUN %d ===\n", runNum)
			}

			results <- success
		}(i)
	}

	wg.Wait()
	close(results)

	// Collect results
	passed := 0
	failed := 0
	for result := range results {
		if result {
			passed++
		} else {
			failed++
		}
	}

	fmt.Printf("\n=== Results ===\n")
	fmt.Printf("Passed: %d/%d (%.2f%%)\n", passed, numRuns, float64(passed)/float64(numRuns)*100)
	fmt.Printf("Failed: %d/%d (%.2f%%)\n", failed, numRuns, float64(failed)/float64(numRuns)*100)

	if failed > 0 && passed > 0 {
		fmt.Printf("\n🔍 NON-DETERMINISM DETECTED!\n")
		fmt.Printf("The test shows inconsistent results, indicating a race condition or non-deterministic behavior.\n")
	} else if failed == 0 {
		fmt.Printf("\n✅ All tests passed - no non-determinism detected in this sample.\n")
	} else {
		fmt.Printf("\n❌ All tests failed - there might be a consistent bug.\n")
	}
}
