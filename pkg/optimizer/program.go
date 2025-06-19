package optimizer

import (
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// BPFProgram represents a BPF program loaded from an ELF file
type BPFProgram struct {
	FilePath string
	ELFFile  *elf.File
	Sections map[string]*Section
}

// NewBPFProgram creates a new BPF program from an ELF file
func NewBPFProgram(filePath string) (*BPFProgram, error) {
	// Open the ELF file
	elfFile, err := elf.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file: %v", err)
	}

	prog := &BPFProgram{
		FilePath: filePath,
		ELFFile:  elfFile,
		Sections: make(map[string]*Section),
	}

	// Process symbols and sections
	if err := prog.processSections(); err != nil {
		elfFile.Close()
		return nil, fmt.Errorf("failed to process sections: %v", err)
	}

	return prog, nil
}

// processSections extracts and optimizes BPF code sections
func (prog *BPFProgram) processSections() error {
	// Get symbol table
	symbols, err := prog.ELFFile.Symbols()
	if err != nil {
		return fmt.Errorf("failed to read symbols: %v", err)
	}

	// Process each function symbol
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
			section := prog.ELFFile.Sections[symbol.Section]
			if section == nil {
				continue
			}

			// Read section data
			data, err := section.Data()
			if err != nil {
				continue
			}

			// Skip empty sections
			if len(data) == 0 {
				continue
			}

			// Convert to hex string and create optimized section
			hexData := hex.EncodeToString(data)
			optimizedSection, err := NewSection(hexData, section.Name)
			if err != nil {
				fmt.Printf("Warning: failed to process section %s: %v\n", section.Name, err)
				continue
			}

			prog.Sections[section.Name] = optimizedSection
		}
	}

	return nil
}

// Save saves the optimized program to a new ELF file
func (prog *BPFProgram) Save(outputPath string) error {
	// This is a simplified implementation
	// A full implementation would need to properly reconstruct the ELF file
	// with modified section contents while preserving other metadata

	// For now, we'll create a basic implementation that copies the original
	// file and patches the modified sections

	// Copy original file
	if err := copyFile(prog.FilePath, outputPath); err != nil {
		return fmt.Errorf("failed to copy original file: %v", err)
	}

	// Open the copied file for modification
	file, err := os.OpenFile(outputPath, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %v", err)
	}
	defer file.Close()

	// Parse the copied ELF file
	outputELF, err := elf.NewFile(file)
	if err != nil {
		return fmt.Errorf("failed to parse output ELF: %v", err)
	}

	// Update sections with optimized data
	for sectionName, optimizedSection := range prog.Sections {
		if err := prog.updateSectionInFile(file, outputELF, sectionName, optimizedSection); err != nil {
			fmt.Printf("Warning: failed to update section %s: %v\n", sectionName, err)
		}
	}

	return nil
}

// updateSectionInFile updates a section in the ELF file with optimized data
func (prog *BPFProgram) updateSectionInFile(file *os.File, elfFile *elf.File, sectionName string, section *Section) error {
	// Find the section in the ELF file
	var targetSection *elf.Section
	for _, s := range elfFile.Sections {
		if s.Name == sectionName {
			targetSection = s
			break
		}
	}

	if targetSection == nil {
		return fmt.Errorf("section %s not found", sectionName)
	}

	// Get optimized data
	optimizedData := section.Dump()

	// Check if the optimized data fits in the original section
	if uint64(len(optimizedData)) > targetSection.Size {
		return fmt.Errorf("optimized data is larger than original section")
	}

	// Write optimized data to the section offset in the file
	_, err := file.WriteAt(optimizedData, int64(targetSection.Offset))
	if err != nil {
		return fmt.Errorf("failed to write optimized data: %v", err)
	}

	// If the optimized data is smaller, pad with zeros
	if uint64(len(optimizedData)) < targetSection.Size {
		padding := make([]byte, targetSection.Size-uint64(len(optimizedData)))
		_, err = file.WriteAt(padding, int64(targetSection.Offset)+int64(len(optimizedData)))
		if err != nil {
			return fmt.Errorf("failed to write padding: %v", err)
		}
	}

	return nil
}

// Close closes the ELF file
func (prog *BPFProgram) Close() error {
	if prog.ELFFile != nil {
		return prog.ELFFile.Close()
	}
	return nil
}

// GetOptimizationStats returns statistics about the optimizations applied
func (prog *BPFProgram) GetOptimizationStats() map[string]interface{} {
	stats := make(map[string]interface{})

	totalInstructions := 0
	optimizedInstructions := 0
	nopInstructions := 0

	for sectionName, section := range prog.Sections {
		sectionStats := make(map[string]int)
		sectionStats["total"] = len(section.Instructions)

		nops := 0
		for _, inst := range section.Instructions {
			if inst.IsNOP() {
				nops++
			}
		}
		sectionStats["nops"] = nops
		sectionStats["active"] = len(section.Instructions) - nops

		stats[sectionName] = sectionStats

		totalInstructions += len(section.Instructions)
		nopInstructions += nops
		optimizedInstructions += nops
	}

	stats["summary"] = map[string]interface{}{
		"total_instructions":     totalInstructions,
		"optimized_instructions": optimizedInstructions,
		"nop_instructions":       nopInstructions,
		"optimization_ratio":     float64(optimizedInstructions) / float64(totalInstructions),
	}

	return stats
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
