/*
@File : ipDBUtil.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 08:58
*/

package util

import (
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/types"
	"analysePDNSByMonth/variables"
	"bufio"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

/*
	根据MaxMind数据库获得IP地理信息，返回示例：中国大陆;China;CN;00001
 */
func GetIPGeoByMM(ips string, mmdb *geoip2.Reader, v4Flag bool, v6Flag bool) string {
	ipList := strings.Split(ips, ";")
	geoList := []string{"null", "null", "null", "null"}
	for _, ip := range ipList {
		ipIP := net.ParseIP(ip)
		record, err := mmdb.Country(ipIP)
		if err != nil || record.Country.GeoNameID == 0{
			continue
		}
		if ((ipIP.To4() != nil) && v4Flag) || ((ipIP.To4() == nil) && v6Flag) {
			geoList[constants.MMCNNameIndex] = record.Country.Names["zh-CN"]
			if geoList[constants.MMCNNameIndex] == "中国" {
				geoList[constants.MMCNNameIndex] = "中国大陆"
			}
			if geoList[constants.MMCNNameIndex] == "香港" || geoList[constants.MMCNNameIndex] == "台湾" || geoList[constants.MMCNNameIndex] == "澳门" {
				geoList[constants.MMCNNameIndex] = "中国" + geoList[constants.MMCNNameIndex]
			}
			geoList[constants.MMENNameIndex] = record.Country.Names["en"]
			geoList[constants.MMCodeIndex] = record.Country.IsoCode
			geoList[constants.MMIDIndex] = strconv.Itoa(int(record.Country.GeoNameID))
			break
		}
	}
	//return strings.Join(geoList, ";")
	return geoList[constants.MMCodeIndex]
}

/*
	根据MaxMind数据库获得IP地理信息，返回示例：CN
 */
func GetSingleIPGeoByMM(ips string, mmdb *geoip2.Reader) string {
	ipIP := net.ParseIP(ips)
	record, err := mmdb.Country(ipIP)
	if err != nil || record.Country.GeoNameID == 0 {
		return "null"
	}
	return record.Country.IsoCode
}

/*
	根据MaxMind数据库获得IP地理信息，返回示例：中国大陆;China;CN;00001
 */
func GetIPGeosPercentByMM(ips string, mmdb *geoip2.Reader, v4Flag bool, v6Flag bool) float64 {
	ipList := strings.Split(ips, ";")
	geoMap := make(map[string]int64)
	var total int64 = 0
	firstGeo := ""
	for _, ip := range ipList {
		ipIP := net.ParseIP(ip)
		record, err := mmdb.Country(ipIP)
		if err != nil || record.Country.GeoNameID == 0{
			continue
		}
		if ((ipIP.To4() != nil) && v4Flag) || ((ipIP.To4() == nil) && v6Flag) {
			geoCNN := record.Country.Names["zh-CN"]
			if geoCNN == "中国" {
				geoCNN = "中国大陆"
			}
			if geoCNN == "香港" || geoCNN == "台湾" || geoCNN == "澳门" {
				geoCNN = "中国" + geoCNN
			}
			geoMap[geoCNN]++
			total++
			if total == 1 {
				firstGeo = geoCNN
			}
		}
	}
	if total == 0{
		return 1.0
	} else {
		return float64(geoMap[firstGeo]) / float64(total)
	}
}

/*
	构建简称、中文国家名字典
 */
func GetISOCNMap(fileName string) {
	timeNow := time.Now()
	LogRecord("Excuting: " + fileName)

	srcFile, err := os.Open(fileName)
	if err != nil {
		LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	br := bufio.NewReader(srcFile)

	variables.IsoCNNameMap = make(types.TPMSS, 200)

	for {
		geoInfoBytes, _, e := br.ReadLine()
		if e == io.EOF {
			break
		}
		geoInfo := string(geoInfoBytes)
		geoInfoList := strings.Split(geoInfo, "\t")
		iso := geoInfoList[constants.ISOIndex]
		cn := strings.Trim(geoInfoList[constants.CNNameIndex], "\"")
		//if _, ok := geoMap[iso]; !ok {
		if cn == "中国" {
			cn = "中国大陆"
		}
		if cn == "香港" || cn == "台湾" || cn == "澳门" {
			cn = "中国" + cn
		}
		variables.IsoCNNameMap[iso] = cn
		//}
	}

	variables.IsoCNNameMap[constants.TotalTimesString] = ""

	LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	LogRecord("Ending: " + fileName)
}

