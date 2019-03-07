/*
@File : test_test.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-11 14:12
*/

package test

import (
	"analysePDNSByMonth/analyse"
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/types"
	"analysePDNSByMonth/util"
	"analysePDNSByMonth/variables"
	"context"
	"encoding/json"
	"fmt"
	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

/*
	测试主函数，先执行
 */
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestUnionRes(t *testing.T) {
	var res0Map = make(types.TPMSTPMSTPMSI64)
	var resMap = make(types.TPMSTPMSTPMSI64)
	variables.DNSDateSpec = "201902"
	variables.DNSDateBefore = "201901"

	res := `{"v4地理":{"中国大陆":{"201902":103818,"总计":103818},"中国香港":{"201902":12,"总计":12},"俄罗斯":{"201902":10,"总计":10},"奥地利":{"201902":11,"总计":11},"德国":{"201902":1,"总计":1},"新加坡":{"201902":1,"总计":1},"美国":{"201902":107,"总计":107},"英国":{"201902":1,"总计":1},"荷兰":{"201902":10,"总计":10},"越南":{"201902":8,"总计":8}},"v6地理":{"中国大陆":{"201902":1,"总计":1},"中国香港":{"201902":12,"总计":12},"俄罗斯":{"201902":10,"总计":10},"印度尼西亚":{"201902":8,"总计":8},"德国":{"201902":1,"总计":1},"新加坡":{"201902":578,"总计":578},"澳大利亚":{"201902":15,"总计":15},"瑞士":{"201902":11,"总计":11},"美国":{"201902":103341,"总计":103341},"英国":{"201902":5,"总计":5},"荷兰":{"201902":6,"总计":6}}}`
	err := json.Unmarshal([]byte(res), &resMap)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(resMap)
	}

	res0 := `{"v4地理":{"中国大陆":{"201901":103818,"总计":103818},"中国香港":{"201901":12,"总计":12},"俄罗斯":{"201901":10,"总计":10},"奥地利":{"201901":11,"总计":11},"德国":{"201901":1,"总计":1},"新加坡":{"201901":1,"总计":1},"美国":{"201901":107,"总计":107},"英国":{"201901":1,"总计":1},"荷兰":{"201901":10,"总计":10},"越南":{"201901":8,"总计":8}},"v6地理":{"中国大陆":{"201901":1,"总计":1},"中国香港":{"201901":12,"总计":12},"俄罗斯":{"201901":10,"总计":10},"印度尼西亚":{"201901":8,"总计":8},"德国":{"201901":1,"总计":1},"新加坡":{"201901":578,"总计":578},"澳大利亚":{"201901":15,"总计":15},"瑞士":{"201901":11,"总计":11},"美国":{"201901":103341,"总计":103341},"英国":{"201901":5,"总计":5},"荷兰":{"201901":6,"总计":6}}}`
	err0 := json.Unmarshal([]byte(res0), &res0Map)
	if err != nil {
		fmt.Println(err0.Error())
	} else {
		fmt.Println(resMap)
	}

	// 增加v46各自独有的国家
	for country, _ := range resMap[constants.V4GeoString] {
		if resMap[constants.V6GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			resMap[constants.V6GeoString][country] = tempMap
			resMap[constants.V6GeoString][country][variables.DNSDateSpec] = 0
			resMap[constants.V6GeoString][country][constants.TotalTimesString] = 0
		}
	}
	for country, _ := range resMap[constants.V6GeoString] {
		if resMap[constants.V4GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			resMap[constants.V4GeoString][country] = tempMap
			resMap[constants.V4GeoString][country][variables.DNSDateSpec] = 0
			resMap[constants.V4GeoString][country][constants.TotalTimesString] = 0
		}
	}

	for country, _ := range res0Map[constants.V4GeoString] {
		if res0Map[constants.V6GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			res0Map[constants.V6GeoString][country] = tempMap
			res0Map[constants.V6GeoString][country][variables.DNSDateSpec] = 0
			res0Map[constants.V6GeoString][country][constants.TotalTimesString] = 0
		}
	}
	for country, _ := range res0Map[constants.V6GeoString] {
		if res0Map[constants.V4GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			res0Map[constants.V4GeoString][country] = tempMap
			res0Map[constants.V4GeoString][country][variables.DNSDateSpec] = 0
			res0Map[constants.V4GeoString][country][constants.TotalTimesString] = 0
		}
	}

	fmt.Println(resMap)
	fmt.Println(res0Map)

}

func TestHello(t *testing.T) {
	host := "www.baidu.com;www.google.com;"
	fmt.Println(len(strings.Split(host, ";")))
}

func TestGeoDiff(t *testing.T) {
	fileName := "/Users/ida/文件/项目文件/ipv6测量/ipv6数据/pdns_ipv6/analyse_old/part-00001"
	analyse.GetGeoPercentByFile(fileName)
}

func TestReg(t *testing.T) {
	RegDate := `[\d]{4}((0[1-9])|1[0-2])`
	if m, _ := regexp.MatchString(RegDate, "201901"); m{
		fmt.Println(true)
	} else{
		fmt.Println(false)
	}
}

func TestPrepareFileDir(t *testing.T) {
	fileName := "test/test-data/pdns_ipv6"
	analyse.PrepareFileDir(fileName)
}

/*
func TestSearchDir(t *testing.T) {
	folderList, e := ioutil.ReadDir("/Users/ida/文件/项目文件/ipv6测量/ipv6数据/pdns_ipv6/analyse_new/")
	if e != nil {
		fmt.Println("read dir error")
		return
	}
	for _, folderInfo := range folderList {
		if util.IsTheDNSFolder(folderInfo) {
			folderName := "/Users/ida/文件/项目文件/ipv6测量/ipv6数据/pdns_ipv6/analyse_new/" + folderInfo.Name() + "/"
			fmt.Println(folderName)

			fileList, e := ioutil.ReadDir(folderName)
			if e != nil {
				fmt.Println("read dir error")
				return
			}
			for _, fi := range fileList {
				if util.IsTheDNSFile(fi) {
					fileName := folderName + fi.Name()
					fmt.Println(fileName)
				}
			}
		}
	}
}

func TestUnionFile(t *testing.T) {
	fileDir := "test/test-data/pdns_ipv6/"
	util.UnionFileOnDir(fileDir, fileDir + constants.DNSFileUnionName + constants.DNSFileTempExtion)
}
*/

func TestGetCurPath(t *testing.T) {
	fmt.Println(util.GetCurPath())
}

/*
	测试文件目录
 */
func TestFileDir(t *testing.T) {
	fmt.Print(string(os.PathSeparator))
}

/*
	测试util.EndLog()
 */
func TestEndLog(t *testing.T) {
	util.LogRecord("测试")
	analyse.EndLog()
}

/*
	测试util.GetLines()
 */
func TestGetLines(t *testing.T) {
	fileName := "part-00000"
	util.GetLines(fileName)
}

/*
	测试Excel
 */
func TestExcel(t *testing.T) {
	xlsx, _ := excelize.OpenFile("test/test-data/pdns_ipv6/result/test.xlsx")
	xlsx.DeleteSheet("Sheet1")
	index := xlsx.NewSheet("Sheet2")
	xlsx.SetCellValue("Sheet2", "A2", "Hello world.")
	xlsx.SetCellValue("Sheet2", "A1", "Hello world.")
	index = xlsx.NewSheet("Sheet2")
	xlsx.SetCellValue("Sheet2", "A2", "Hello.")
	xlsx.SetCellValue("Sheet2", "A3", "Hello.")
	xlsx.SetActiveSheet(index)

	if xlsx.SearchSheet("Sheet2", "hello.") == nil {
		fmt.Println("not")

	}

	err := xlsx.SaveAs("test/test-data/pdns_ipv6/result/test.xlsx")
	if err != nil {
		fmt.Println(err)
	}
}

/*
	测试MaxMind数据库
 */
func TestMaxMindDB(t *testing.T) {
	db, err := geoip2.Open("GeoLite2-Country.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// If you are using strings that may be invalid, check that ip is not nil
	ip := net.ParseIP("0.0.0.0")
	record, err := db.Country(ip)
	if err != nil {
		log.Fatal(err)
	}
	if record.Country.GeoNameID == 0 {
		fmt.Println("null")
		return
	}
	fmt.Println(record.Country.Names["en"])
	fmt.Println(record.Country.Names["zh-CN"])
	fmt.Println(record.Country.IsoCode)
	fmt.Println(record.Country.GeoNameID)
}

func TestDNS(t *testing.T) {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)

	host := "baidu.com"

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	//r, _, err := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	const timeout = 1000 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	r, _, err := c.ExchangeContext(ctx, m, net.JoinHostPort(config.Servers[0], config.Port))
	if r == nil {
		log.Fatalf("*** error: %s\n", err.Error())
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Fatalf(" *** invalid answer name %s after MX query for %s\n", os.Args[1], os.Args[1])
	}
	// Stuff must be in the answer section
	for _, a := range r.Answer {
		fmt.Printf("%s\n", strings.Split(a.String(), "\t")[4])
	}
}
