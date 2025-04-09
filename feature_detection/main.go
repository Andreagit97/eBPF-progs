package main

import (
	"errors"
	"flag"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	skipRlimit := flag.Bool("skip-rlimit", false, "Skip removing the memlock rlimit")
	flag.Parse()

	if !*skipRlimit {
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Println("Skipping rlimit removal as requested")
	}

	var requiredFuncs = []asm.BuiltinFunc{
		asm.FnMapLookupElem,
		asm.FnMapUpdateElem,
		asm.FnMapDeleteElem,
		asm.FnPerfEventOutput,
		asm.FnPerfEventRead,
	}
	for _, rf := range requiredFuncs {
		if err := features.HaveProgramHelper(ebpf.Kprobe, rf); err != nil {
			if errors.Is(err, ebpf.ErrNotSupported) {
				log.Fatalf("ebpf helper %s not supported: %s", rf.String(), err)
			} else {
				log.Fatalf("error checking for ebpf helper %s support: %s", rf.String(), err)
			}
		}
	}

	log.Println("All required ebpf helpers are supported")
}
