package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf ./bpf/main.c -- -I/usr/include/ -I../include

const SO_ATTACH_BPF = 50

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
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	if err := loadBpfObjects(&objs, &opts); err != nil {
		log.Fatalf("loading objects: %v", err)
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
	fmt.Println("Packet stats:")

	var ipv4 uint64
	var ipv6 uint64
	for {
		time.Sleep(time.Second)
		objs.Ip4Counter.Get(&ipv4)
		objs.Ip6Counter.Get(&ipv6)
		fmt.Printf("\tIP4: %v IP6: %v\n", ipv4, ipv6)
	}
}

func openRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: htons(syscall.ETH_P_ALL),
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
