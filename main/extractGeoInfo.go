/*
@File : extractGeoInfo.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-15 20:55
*/

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

/*
	去除重复TLD
 */
func extractCNISO(fileName string, fileNameNew string) {
	srcFile, err := os.Open(fileName)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	br := bufio.NewReader(srcFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0

	var geoMap= make(map[string]string, 200)

	for {
		if readedCount%10000 == 0 {
			readedCount = 0
			fmt.Printf("read: %d\n", readedTotal)
		}
		dnsRecordBytes, _, e := br.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		geoInfo := string(dnsRecordBytes)
		geoInfoList := strings.Split(geoInfo, ",")
		iso := geoInfoList[4]
		cn := geoInfoList[5]
		if _, ok := geoMap[iso]; !ok {
			geoMap[iso] = cn
		}

	}
	fmt.Printf("total: %d\n", readedTotal)

	fw, err := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw.Close()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

	// 保存中文国家
	readedTotal = 1
	for iso, cn := range geoMap {
		fmt.Printf("writing total: %d\n", readedTotal)
		readedTotal++
		_, err = outWFile.WriteString(fmt.Sprintf("%s\t%s\n", iso, cn))
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		outWFile.Flush()
	}
}

func main() {
	f := "/Users/ida/文件/项目文件/ipv6测量/ipv6数据/db_ip/GeoLite2-City-CSV_20190312/GeoLite2-City-Locations-zh-CN.csv"
	fn := "/Users/ida/文件/项目文件/ipv6测量/ipv6数据/db_ip/GeoLite2-City-CSV_20190312/isoCNName.csv"
	extractCNISO(f, fn)
}
