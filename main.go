package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Input file path is required as first argument")
	}

	inputFile := os.Args[1]
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	command, err := parse(data)
	if err != nil {
		log.Fatalf("Failed to parse report: %v", err)
	}

	if command == "" {
		log.Println("No updates required")
		os.Exit(0)
	}

	fmt.Println(command)
}
