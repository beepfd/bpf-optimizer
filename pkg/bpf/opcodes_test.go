package bpf

import "testing"

func TestBPFConstants(t *testing.T) {
	// Test BPF instruction classes
	if BPF_LD != 0x00 {
		t.Errorf("BPF_LD should be 0x00, got 0x%02x", BPF_LD)
	}

	if BPF_ALU != 0x04 {
		t.Errorf("BPF_ALU should be 0x04, got 0x%02x", BPF_ALU)
	}

	if BPF_JMP != 0x05 {
		t.Errorf("BPF_JMP should be 0x05, got 0x%02x", BPF_JMP)
	}

	// Test ALU operations
	if ALU_ADD != 0x00 {
		t.Errorf("ALU_ADD should be 0x00, got 0x%02x", ALU_ADD)
	}

	if ALU_MOV != 0xb0 {
		t.Errorf("ALU_MOV should be 0xb0, got 0x%02x", ALU_MOV)
	}

	// Test jump operations
	if JMP_CALL != 0x80 {
		t.Errorf("JMP_CALL should be 0x80, got 0x%02x", JMP_CALL)
	}

	if JMP_EXIT != 0x90 {
		t.Errorf("JMP_EXIT should be 0x90, got 0x%02x", JMP_EXIT)
	}

	// Test NOP constant
	if NOP != "0500000000000000" {
		t.Errorf("NOP should be '0500000000000000', got '%s'", NOP)
	}
}

func TestAtomicConstants(t *testing.T) {
	// Test atomic operations match ALU operations
	if ATOMIC_ADD != ALU_ADD {
		t.Errorf("ATOMIC_ADD should equal ALU_ADD")
	}

	if ATOMIC_OR != ALU_OR {
		t.Errorf("ATOMIC_OR should equal ALU_OR")
	}

	if ATOMIC_AND != ALU_AND {
		t.Errorf("ATOMIC_AND should equal ALU_AND")
	}

	if ATOMIC_XOR != ALU_XOR {
		t.Errorf("ATOMIC_XOR should equal ALU_XOR")
	}
}
