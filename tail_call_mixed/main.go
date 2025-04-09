package main

import (
	"log"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf ./bpf/main.c -- -I/usr/include/ -I../include

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		if objs.SysEnter.VerifierLog != "" {
			log.Printf("SysEnter verifier log:\n%s", objs.SysEnter.VerifierLog)
		}
		log.Fatalf("loading objects: %v", err)
	}
	objs.Close()

	log.Println("Ebpf configuration completed.")

}
