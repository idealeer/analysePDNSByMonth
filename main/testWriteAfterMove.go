/*
@File : testWriteAfterMove.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-15 14:27
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func OpenFile(fileName string) *os.File {
	fw, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	return fw
}

func WriteFile(fw *os.File, str string) {
	log.SetOutput(fw)
	log.Printf(str)
	log.SetOutput(os.Stdout)
	log.Printf(str)
}

func CloseFile(fw *os.File) {
	fw.Close()
}

func MoveFile(fileName string, fileNameNew string) {
	err := os.Rename(fileName, fileNameNew)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	} else {
		fmt.Printf("Move ok: %s -> %s\n", fileName, fileNameNew)
	}
}

func RemoveFile(fileName string) {
	err := os.RemoveAll(fileName)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	} else {
		fmt.Printf("Remove ok: %s\n", fileName)
	}
}

func TestWriteAfterMove(fileName string, fileNameNew string) {
	fw := OpenFile(fileName)
	WriteFile(fw, "Before Move, fw.Name: " + fw.Name() + "\n")
	MoveFile(fileName, fileNameNew)
	WriteFile(fw, "After Move, fw.Name: " + fw.Name() + "fileName: " + fileNameNew + "\n")
	CloseFile(fw)
}

func TestWriteRemoveMove(fileName string, fileNameNew string) {
	fw := OpenFile(fileName)
	WriteFile(fw, "Before Move, fw.Name: " + fw.Name() + "\n")
	MoveFile(fileName, fileNameNew)
	RemoveFile(fileName)
	WriteFile(fw, "After Move, fw.Name: " + fw.Name() + "fileName: " + fileNameNew + "\n")
	CloseFile(fw)
}

var (
	file	string
	fileNew	string
)

func init() {
	flag.StringVar(&file, "file", "",
		fmt.Sprintf("%s", "file full name"))

	flag.StringVar(&fileNew, "file-new", "",
		fmt.Sprintf("%s", "new file full name"))
}

func main() {
	flag.Parse()
	TestWriteAfterMove(file, fileNew)
}
