/*
@File : main.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-16 20:30
*/

package main

import (
	"analysePDNSByMonth/types"
	"analysePDNSByMonth/util"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func run1() {
	cmd := exec.Command("logShow", "|", "wc", "-l")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	cmd.Run()
	cmd.Wait()
}

// 直接输出到屏幕
func run2() {
	c1 := exec.Command("logShow")
	c2 := exec.Command("wc", "-l")
	c2.Stdin, _ = c1.StdoutPipe()	// c1的输出作为c2的输入
	c2.Stdout = os.Stdout
	c2.Stderr = os.Stderr
	c2.Start()
	c1.Run()
	c2.Wait()
}

func run3() {
	c1 := exec.Command("ps", "-eaf")
	c2 := exec.Command("grep", `"nginx: master"`)
	c3 := exec.Command("grep", "-v", `"grep"`)
	c4 := exec.Command("awk", `'{print $2}'`)
	c2.Stdin, _ = c1.StdoutPipe()
	c3.Stdin, _ = c2.StdoutPipe()
	c4.Stdin, _ = c3.StdoutPipe()

	c4.Stdout = os.Stdout
	c4.Stderr = os.Stderr
	c4.Start()
	c3.Start()
	c2.Start()
	c1.Run()
	c4.Wait()
}

// 直接输出到屏幕
func run4() {
	cmd := exec.Command("/bin/sh", "-c", `ps -eaf|grep "nginx: master"|grep -v "grep"|awk '{print $2}'`)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	cmd.Run()
	cmd.Wait()
}

func runn() {

	dm := "www.baidu.com"
	zdns := ""
	s := fmt.Sprintf("echo %s | %s ALOOKUP", dm, zdns)
	//s := `echo www.baidu.com | /Users/ida/文件/程序文件/Go文件/bin/zdns ALOOKUP`


	cmd := exec.Command("/bin/sh", "-c", s)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	// 保证关闭输出流
	defer stdout.Close()
	// 运行命令
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	// 读取输出结果
	opBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(opBytes))
}

/*
	执行bash命令
 */
func ExcuteCmd(exe string, argu []string) string {
	cmd := exec.Command(exe, argu...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	// 保证关闭输出流
	defer stdout.Close()
	// 运行命令
	if err := cmd.Start(); err != nil {
		fmt.Printf("Error: %s", err.Error())
		os.Exit(1)
	}
	// 读取输出结果
	opBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		os.Exit(1)
	}
	return string(opBytes)
}

func OsCmdMv() {
	op := ""
	np := ""
	err := os.Rename(op, np)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("rename ok")
	}
}

func OsCmdRm() {
	op := fmt.Sprintf("%s%s01/", "", "201901")
	err := os.RemoveAll(op)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("remove ok")
	}
}

func GetParDirOnDir() {
	fmt.Println(util.GetParDir(strings.TrimRight("", string(os.PathSeparator))))

}

func benchmarkStringFunction(n int, index int) (d time.Duration) {
	v := "abcd efg hijk lmn"
	var s string
	var buf bytes.Buffer

	t0 := time.Now()
	for i := 0; i < n; i++ {
		switch index {
		case 0: // fmt.Sprintf
			s = fmt.Sprintf("%s[%s]", s, v)
		case 1: // string +
			s = s + "[" + v + "]"
		case 2: // strings.Join
			s = strings.Join([]string{s, "[", v, "]"}, "")
		case 3: // temporary bytes.Buffer
			b := bytes.Buffer{}
			b.WriteString("[")
			b.WriteString(v)
			b.WriteString("]")
			s = b.String()
		case 4: // stable bytes.Buffer			kkkkkkkkkk
			buf.WriteString("[")
			buf.WriteString(v)
			buf.WriteString("]")
		}

		if i == n-1 {
			if index == 4 { // for stable bytes.Buffer
				s = buf.String()
			}
			fmt.Println(len(s)) // consume s to avoid compiler optimization
		}
	}
	t1 := time.Now()
	d = t1.Sub(t0)
	fmt.Printf("time of way(%d)=%v\n", index, d)
	return d
}

func TestAddString() {
	k := 5
	d := [5]time.Duration{}
	for i := 0; i < k; i++ {
		d[i] = benchmarkStringFunction(1, i)
	}
}

func TestUnionString() {
	n := strconv.FormatInt(1, 10)

	var buf bytes.Buffer

	t0 := time.Now()
	buf.WriteByte('\t')
	buf.WriteString(n)
	buf.WriteByte('\t')
	buf.WriteString(n)
	buf.WriteByte('\n')

	t1 := time.Now()
	d := t1.Sub(t0)
	fmt.Printf("time %v\n", d)
	fmt.Println(buf.String())
	buf.Reset()


	t0 = time.Now()

	s := fmt.Sprintf("%s%s%s", "[", n, "]")

	t1 = time.Now()
	d = t1.Sub(t0)
	fmt.Printf("time %v\n", d)
	fmt.Println(s)
}

func Test201811China(fileName string) {
	timeNow := time.Now()

	srcFile, err := os.Open(fileName)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		os.Exit(1)
	}
	defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	br := bufio.NewReader(srcFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0

	var domainMap = make(map[string]string)
	totalChinaGeoUD := 0
	totalTimes := 0

	for {
		if readedCount%1000000 == 0 {
			readedCount = 0
			fmt.Printf("readed: %d, cost: %ds\n", readedTotal, time.Now().Sub(timeNow)/time.Second)
		}
		dnsRecordBytes, _, e := br.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		dnsRecord := string(dnsRecordBytes)
		dnsRecordList := strings.Split(dnsRecord, "\t")
		dnsRecordDomain := dnsRecordList[0]
		times, _ := strconv.Atoi(dnsRecordList[1])
		geo := dnsRecordList[4]
		if geo == "CN" {
			if _, ok := domainMap[dnsRecordDomain]; !ok {
				domainMap[dnsRecordDomain] = ""
				totalChinaGeoUD ++
			}
			totalTimes += times
		}
	}
	fmt.Printf("total: %d, cost: %ds\n", readedTotal, time.Now().Sub(timeNow)/time.Second)
	fmt.Printf("total China uniqDomain: %d, cost: %ds\n", totalChinaGeoUD, time.Now().Sub(timeNow)/time.Second)
	fmt.Printf("total China times: %d, cost: %ds\n", totalTimes, time.Now().Sub(timeNow)/time.Second)

}

func main() {
	var l = make(types.DCIList, 0)
	l = append(l, types.DCI{"360.net", 100})
	lb, _ := json.Marshal(l)

	fmt.Println(string(lb))
}
