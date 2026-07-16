package main

import (
	"fmt"
	"github.com/singchia/go-xtables/iptables"
)

func main() {
	for i := 0; i < 20; i++ {
		fmt.Printf("%d: %s\n", i, iptables.RejectType(i).String())
	}
}
