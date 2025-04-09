package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
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
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_open", objs.Test, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	log.Println("-- Counting syscalls")

	var counter uint64
	for {
		if err := objs.Counter.Get(&counter); err != nil {
			log.Fatalf("getting counter: %v", err)
		}
		log.Println("Counting open syscall... ", counter)
		time.Sleep(1 * time.Second)
	}
}
