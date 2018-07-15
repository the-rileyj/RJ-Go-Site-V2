package main

import (
	"fmt"
	"os"
	"os/exec"
)

func test() {
	command := exec.Command("cmd", "/c", "")
	command.Env = os.Environ()
	if out, err := command.Output(); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(out)
	}
}
