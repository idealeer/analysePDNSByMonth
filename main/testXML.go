package main

import (
	"encoding/json"
	"fmt"
	"github.com/n0ncetonic/nmapxml"
)

func main() {
	scanData, err := nmapxml.Readfile("/Users/ida/文件/项目文件/ipv6测量/ipv6数据/pdns_ipv6/analyse_new/record_history/temp-201902/CN/nmap.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	jsonData, err := json.Marshal(scanData.Host[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%+v", string(jsonData))
}
