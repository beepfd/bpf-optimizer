package bpf

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// 解析操作码
// 操作码: 0x62 = 98 (十进制)
// 指令类别: 0x62 & 0x07 = 0x02 = BPF_ST (存储立即数)
// 内存模式: 0x62 & 0xE0 = 0x60 = BPF_MEM (内存访问)
// 数据大小: 0x62 & 0x18 = 0x00 = 32位
func parseOpcode(hexStr string) (uint8, error) {
	opcode, err := strconv.ParseUint(hexStr[0:2], 16, 8)
	if err != nil {
		return 0, fmt.Errorf("failed to parse opcode: %v", err)
	}
	return uint8(opcode), nil
}

// 解析寄存器字段
// 寄存器字段: 0x0a
// dst寄存器: 0x0a & 0x0F = 0x0a = r10 (栈指针)
// src寄存器: (0x0a & 0xF0) >> 4 = 0x00 = r0 (源寄存器)
func parseRegisters(hexStr string) (uint8, uint8, error) {
	regs, err := strconv.ParseUint(hexStr[2:4], 16, 8)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse registers: %v", err)
	}
	dstReg := uint8(regs & 0x0F)
	srcReg := uint8((regs & 0xF0) >> 4)
	return dstReg, srcReg, nil
}

// 解析偏移量
// off = insn[6:8] + insn[4:6]  # 小端字节序
// off = "ff" + "fc" = "fffc"   # 16进制字符串
// 转换为无符号整数
// unsigned_off = int("fffc", 16) = 65532
// 转换为有符号16位整数
// signed_off = to_signed(65532, bits=16)
// 65532 的二进制: 1111111111111100
// 最高位为1，所以是负数
// 计算: 65532 - 2^16 = 65532 - 65536 = -4
func parseOffset(hexStr string) (int16, error) {
	offsetHex := hexStr[6:8] + hexStr[4:6]
	offsetUint, err := strconv.ParseUint(offsetHex, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("failed to parse offset: %v", err)
	}

	// 注意：此处 offset 可以是负数
	// offset = -4 是正确的结果！
	// 这条指令 620afcff00000000 的含义是：
	// 操作: 存储32位立即数到内存
	// 目标: 栈指针(r10) + 偏移量(-4)的位置
	// 值: 0 (立即数部分)
	// 汇编形式: *(u32*)(r10 - 4) = 0
	// 负偏移量-4的作用：
	// 在eBPF中，r10是栈指针，指向栈的"底部"
	// 栈向下增长，所以访问栈上的局部变量需要负偏移量
	// r10 - 4 表示在栈上分配4字节空间存储一个32位值
	// 这是典型的栈变量初始化操作
	return int16(offsetUint), nil
}

// 解析立即数
func parseImmediate(hexStr string) (int32, error) {
	immHex := hexStr[8:16]
	immBytes, err := hex.DecodeString(immHex)
	if err != nil {
		return 0, fmt.Errorf("failed to parse immediate: %v", err)
	}

	return int32(immBytes[0]) | (int32(immBytes[1]) << 8) | (int32(immBytes[2]) << 16) | (int32(immBytes[3]) << 24), nil
}

func BuildTestInstructionFromFile(testFile string) (hexStr string, want []*Instruction) {
	raw, err := os.ReadFile(testFile)
	if err != nil {
		panic(err)
	}

	want = make([]*Instruction, 0)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	// b700000001000000,183,0,0,0,1
	// hexStr: b700000001000000
	// opcode: 183
	// srcReg: 0
	// dstReg: 0
	// offset: 0
	// imm: 1
	for scanner.Scan() {
		line := scanner.Text()
		splited := strings.Split(line, ",")
		hexStr += splited[0]

		opcode, _ := strconv.ParseUint(splited[1], 10, 8)
		srcReg, _ := strconv.ParseUint(splited[2], 10, 8)
		dstReg, _ := strconv.ParseUint(splited[3], 10, 8)
		offset, _ := strconv.ParseInt(splited[4], 10, 16)
		imm, _ := strconv.ParseInt(splited[5], 10, 32)

		want = append(want, &Instruction{
			Raw:    splited[0],
			Opcode: uint8(opcode),
			SrcReg: uint8(srcReg),
			DstReg: uint8(dstReg),
			Offset: int16(offset),
			Imm:    int32(imm),
		})
	}
	return hexStr, want
}
