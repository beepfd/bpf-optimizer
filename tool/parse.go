package tool

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// FormatMapDifference 格式化 map[int][]int 的差异信息
func FormatMapDifference(name string, got, want map[int][]int) string {
	var diff strings.Builder
	diff.WriteString(fmt.Sprintf("%s differences:\n", name))

	// 找出所有涉及的键
	allKeys := make(map[int]bool)
	for k := range got {
		allKeys[k] = true
	}
	for k := range want {
		allKeys[k] = true
	}

	keys := make([]int, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	diffCount := 0
	for _, k := range keys {
		gotVal, gotExists := got[k]
		wantVal, wantExists := want[k]

		if !gotExists && wantExists {
			diff.WriteString(fmt.Sprintf("  Missing key %d: want %v\n", k, wantVal))
			diffCount++
		} else if gotExists && !wantExists {
			diff.WriteString(fmt.Sprintf("  Extra key %d: got %v\n", k, gotVal))
			diffCount++
		} else if !CompareIntSlices(gotVal, wantVal) {
			diff.WriteString(fmt.Sprintf("  Key %d: got %v, want %v\n", k, gotVal, wantVal))
			diffCount++
		}

		// 限制显示的差异数量，避免输出过长
		if diffCount >= 10 {
			diff.WriteString("  ... (more differences exist)\n")
			break
		}
	}

	return diff.String()
}

// FormatIntMapDifference 格式化 map[int]int 的差异信息
func FormatIntMapDifference(name string, got, want map[int]int) string {
	var diff strings.Builder
	diff.WriteString(fmt.Sprintf("%s differences:\n", name))

	// 找出所有涉及的键
	allKeys := make(map[int]bool)
	for k := range got {
		allKeys[k] = true
	}
	for k := range want {
		allKeys[k] = true
	}

	keys := make([]int, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	diffCount := 0
	for _, k := range keys {
		gotVal, gotExists := got[k]
		wantVal, wantExists := want[k]

		if !gotExists && wantExists {
			diff.WriteString(fmt.Sprintf("  Missing key %d: want %d\n", k, wantVal))
			diffCount++
		} else if gotExists && !wantExists {
			diff.WriteString(fmt.Sprintf("  Extra key %d: got %d\n", k, gotVal))
			diffCount++
		} else if gotVal != wantVal {
			diff.WriteString(fmt.Sprintf("  Key %d: got %d, want %d\n", k, gotVal, wantVal))
			diffCount++
		}

		// 限制显示的差异数量
		if diffCount >= 10 {
			diff.WriteString("  ... (more differences exist)\n")
			break
		}
	}

	return diff.String()
}

// CompareIntSliceMap 比较两个 map[int][]int 是否相等
func CompareIntSliceMap(got, want map[int][]int) bool {
	if len(got) != len(want) {
		return false
	}

	for key, gotSlice := range got {
		wantSlice, exists := want[key]
		if !exists {
			return false
		}

		if !CompareIntSlices(gotSlice, wantSlice) {
			return false
		}
	}

	return true
}

// CompareIntIntMap 比较两个 map[int]int 是否相等
func CompareIntIntMap(got, want map[int]int) bool {
	if len(got) != len(want) {
		return false
	}

	for key, gotValue := range got {
		wantValue, exists := want[key]
		if !exists || gotValue != wantValue {
			return false
		}
	}
	return true
}

// CompareIntSlices 比较两个 []int 是否相等（顺序敏感）
func CompareIntSlices(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}

	for i, gotValue := range got {
		if gotValue != want[i] {
			return false
		}
	}

	return true
}

// ParsePythonDictIntSlice 解析 Python 字典格式的文件
func ParsePythonDictIntSlice(filename string) ([]map[int][]int, error) {
	result := make([]map[int][]int, 0)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 为每行创建一个 map
		lineMap := make(map[int][]int)

		// 移除外层的大括号 {}
		line = strings.Trim(line, "{}")
		if line == "" {
			result = append(result, lineMap)
			continue
		}

		// 需要智能分割，考虑数组中的逗号
		pairs := make([]string, 0)
		current := ""
		bracketDepth := 0

		for _, char := range line {
			if char == '[' {
				bracketDepth++
			} else if char == ']' {
				bracketDepth--
			} else if char == ',' && bracketDepth == 0 {
				pairs = append(pairs, strings.TrimSpace(current))
				current = ""
				continue
			}
			current += string(char)
		}
		if current != "" {
			pairs = append(pairs, strings.TrimSpace(current))
		}

		// 解析每个键值对
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}

			// 查找 ': [' 分隔符
			colonIndex := strings.Index(pair, ":")
			if colonIndex == -1 {
				continue
			}

			// 解析键
			keyStr := strings.TrimSpace(pair[:colonIndex])
			key, err := strconv.Atoi(keyStr)
			if err != nil {
				continue
			}

			// 解析值数组
			valueStr := strings.TrimSpace(pair[colonIndex+1:])
			valueStr = strings.TrimSpace(valueStr)

			// 处理数组格式
			if !strings.HasPrefix(valueStr, "[") || !strings.HasSuffix(valueStr, "]") {
				continue
			}

			arrayContent := strings.TrimSpace(valueStr[1 : len(valueStr)-1])
			var values []int
			if arrayContent != "" {
				valueStrs := strings.Split(arrayContent, ",")
				for _, vStr := range valueStrs {
					vStr = strings.TrimSpace(vStr)
					if vStr != "" {
						value, err := strconv.Atoi(vStr)
						if err == nil {
							values = append(values, value)
						}
					}
				}
			}

			lineMap[key] = values
		}

		result = append(result, lineMap)
	}

	return result, scanner.Err()
}

// ParsePythonDictInt 解析节点长度信息文件 (Python字典格式)
func ParsePythonDictInt(filename string) ([]map[int]int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make([]map[int]int, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subResult := make(map[int]int)
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 移除外层的大括号 {}
		line = strings.Trim(line, "{}")
		if line == "" {
			continue
		}

		// 按逗号分割键值对
		pairs := strings.Split(line, ",")
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}

			// 分割键值对 "key: value"
			parts := strings.Split(pair, ":")
			if len(parts) != 2 {
				continue
			}

			// 解析键和值
			keyStr := strings.TrimSpace(parts[0])
			valueStr := strings.TrimSpace(parts[1])

			key, err := strconv.Atoi(keyStr)
			if err != nil {
				continue
			}

			value, err := strconv.Atoi(valueStr)
			if err != nil {
				continue
			}

			subResult[key] = value
		}
		result = append(result, subResult)
	}

	return result, scanner.Err()
}

func ParsePythonDictIntSliceToMapIntBool(line string) (map[int]bool, error) {
	// 移除外层的大括号 {}
	line = strings.Trim(line, "{}")
	if line == "" {
		return nil, errors.New("line is empty")
	}

	// 按逗号分割键值对
	pairs := strings.Split(line, ",")
	nodesDoneMap := make(map[int]bool)
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		key, err := strconv.Atoi(pair)
		if err != nil {
			return nil, err
		}
		nodesDoneMap[key] = true
	}
	return nodesDoneMap, nil
}
