package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf ./bpf/main.c -- -I/usr/include/ -I../include

const SO_ATTACH_BPF = 50

// https://thomasw.dev/post/packet_ignore_outgoing/
const PACKET_IGNORE_OUTGOING = 23

func main() {
	ifaceNameIndex := 0
	switch {
	case len(os.Args) == 2:
		// Use `ip link`
		ifaceName := os.Args[1]
		log.Printf("chosen network iface name %q", ifaceName)
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("lookup network iface %q: %s", ifaceName, err)
		}
		ifaceNameIndex = iface.Index
	case len(os.Args) == 1:
		log.Printf("All network interfaces will be used")
	default:
		log.Fatalf("Usage: %s [network interface]", os.Args[0])
	}

	objs := bpfObjects{}
	opts := ebpf.CollectionOptions{}
	opts.Programs.LogLevel = ebpf.LogLevelInstruction | ebpf.LogLevelStats
	if err := loadBpfObjects(&objs, &opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("\n\nVerifier error: %v\n\n", strings.Join(ve.Log, "\n"))
		} else {
			log.Fatalf("Generic error: %v", err)
		}
	}
	defer objs.Close()

	sock, err := openRawSock(ifaceNameIndex)
	if err != nil {
		log.Fatalf("opening raw socket: %s", err)
	}
	defer syscall.Close(sock)

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, objs.SocketProtocolDispatcher.FD()); err != nil {
		panic(err)
	}

	fmt.Printf("Filtering on all interfaces\n")

	for {
		// Wait for the end...
		time.Sleep(time.Second)
		fmt.Print(".")
	}
}

func openRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}

	// Ignore outgoing packets
	// https://thomasw.dev/post/packet_ignore_outgoing/
	// if err := syscall.SetsockoptInt(sock, syscall.SOL_PACKET, PACKET_IGNORE_OUTGOING, 1); err != nil {
	// 	return 0, err
	// }

	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: htons(syscall.ETH_P_ALL),
		Pkttype:  syscall.PACKET_HOST,
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
