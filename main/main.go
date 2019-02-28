/*
@File : main.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-16 20:30
*/

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
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


func main() {

	//run1()
	//run2()
	runn()
}
