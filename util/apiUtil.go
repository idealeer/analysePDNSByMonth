/*
@File : apiUtil.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-07 19:01
*/

package util

import (
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/types"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func Api2JsonMap(apiFile string, jsonFile string) {
	timeNow := time.Now()
	LogRecord("Excuting: " + apiFile + " -> " + jsonFile)

	// 读入api文件
	apiF, eO := os.Open(apiFile)
	if eO != nil {
		LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
		os.Exit(1)
	}
	defer apiF.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inApiFile := bufio.NewReader(apiF)
	apiString, eR := inApiFile.ReadString('\n')
	if eR == io.EOF || eR != nil {
		LogRecord(fmt.Sprintf("Error: %s is null", apiFile))
		os.Exit(1)
	}

	// 转换api为指定结构
	var CMCS = new(types.CMCList)
	err := json.Unmarshal([]byte(apiString), &CMCS)
	if err != nil {
		LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	// 字典文件
	var resMap = make(types.TPMSTPMSTPMSI64)
	// v4/v6地理是否存在
	if resMap[constants.V4GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		resMap[constants.V4GeoString] = cmcMap
	}
	if resMap[constants.V6GeoString] == nil {
		cmcMap1 := make(types.TPMSTPMSI64)
		resMap[constants.V6GeoString] = cmcMap1
	}

	// 获得年月区间
	ymList, ymLen := GetSpecYMsByYM(constants.YearBeforeStart, constants.MonthBeforeStart, constants.YearBeforeEnd, constants.MonthBeforeEnd)
	// 遍历data, 类似: [{"US", [0,1,2,3,...,]}, {"US_v4", [0,1,2,3,...,]}, ... ,{}]
	apiLen := len(CMCS.Data)
	for i := 0; i < apiLen; i++ {
		countryList := strings.Split(CMCS.Data[i].Country, "_")
		countList := CMCS.Data[i].Counts
		country := countryList[0]
		geo := ""
		if len(countryList) == 1 {
			geo = constants.V6GeoString
		} else {
			geo = constants.V4GeoString
		}
		if resMap[geo][country] == nil {
			tempMap := make(types.TPMSI64)
			resMap[geo][country] = tempMap
		}
		if resMap[geo][constants.TotalTimesString] == nil {
			tempMap := make(types.TPMSI64)
			resMap[geo][constants.TotalTimesString] = tempMap
		}
		for j := 0; j < ymLen; j++ {
			resMap[geo][country][ymList[j]] += countList[j + constants.ApiCountStartIndex]
			resMap[geo][country][constants.TotalTimesString] += countList[j + constants.ApiCountStartIndex]
			resMap[geo][constants.TotalTimesString][ymList[j]] += countList[j + constants.ApiCountStartIndex]
			resMap[geo][constants.TotalTimesString][constants.TotalTimesString] += countList[j + constants.ApiCountStartIndex]
		}
	}

	// 增加v46添加各自独有的国家+所有月份
	for country, _ := range resMap[constants.V4GeoString] {
		if resMap[constants.V6GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			resMap[constants.V6GeoString][country] = tempMap
			// 遍历任一个国家获得月份
			for c, _ := range resMap[constants.V4GeoString] {
				for m, _ := range resMap[constants.V4GeoString][c] {
					resMap[constants.V6GeoString][country][m] = 0
				}
				break
			}
		}
	}
	for country, _ := range resMap[constants.V6GeoString] {
		if resMap[constants.V4GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			resMap[constants.V4GeoString][country] = tempMap
			// 遍历任一个国家获得月份
			for c, _ := range resMap[constants.V6GeoString] {
				for m, _ := range resMap[constants.V6GeoString][c] {
					resMap[constants.V4GeoString][country][m] = 0
				}
				break
			}
		}
	}

	// 保存结果到JSon
	jsonBytes, err := json.Marshal(resMap)
	if err != nil {
		LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	fw, err := os.OpenFile(jsonFile, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw.Close()
	if err != nil {
		LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象
	_, err = outWFile.WriteString(string(jsonBytes) + "\n")
	if err != nil {
		LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	outWFile.Flush()

	LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	LogRecord("Ending: " + apiFile + " -> " + jsonFile)
}
