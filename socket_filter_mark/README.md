# Socket filter

## Scenario 1

Ping localhost

```bash
sudo ping -m 1234 -c 1 127.0.0.1
```

We should see something like this. These are the ICMP echo Requests, the Replies won't be marked so we won't see them.

```text
ping-151979  [003] b..11 25721.924129: bpf_trace_printk: [O] Packet ifx: 1, sport: 3, dport: 8
ping-151979  [003] ..s21 25721.924140: bpf_trace_printk: [I] Packet ifx: 1, sport: 3, dport: 8
```

- First we hit the packet when it exits from the loopback interface.
- Second we hit again when it enter again from the loopback interface.

## Scenario 2

Ping from a docker in the root namespace another docker in a different network namespace

Start nginx server

```bash
docker run -it --rm -p 8080:80 --name web nginx
```

Ping it from a docker in the network namespace

```bash
docker run --network host --privileged --rm -i -t andreater/netshoot:v1 /bin/bash
curl --local-port 8971 127.0.0.1:8080
```

We should see something like this

```text
3-WAY HANDSHAKE
           curl-179843  [001] b..11 33223.507683: bpf_trace_printk: [O] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656154, a: 0, f: S
           curl-179843  [001] ..s21 33223.507695: bpf_trace_printk: [I] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656154, a: 0, f: S
           curl-179843  [001] b.s21 33223.507713: bpf_trace_printk: [O] ifx: 1, sip: 127.0.0.1, sport: 8080, dip: 127.0.0.1, dport: 8971, s: 2040780432, a: 31656155, f: S+A
           curl-179843  [001] ..s21 33223.507717: bpf_trace_printk: [I] ifx: 1, sip: 127.0.0.1, sport: 8080, dip: 127.0.0.1, dport: 8971, s: 2040780432, a: 31656155, f: S+A
           curl-179843  [001] b..11 33223.507732: bpf_trace_printk: [O] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656155, a: 2040780433, f: A
           curl-179843  [001] ..s21 33223.507734: bpf_trace_printk: [I] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656155, a: 2040780433, f: A

CURL SEND SOME DATA
           curl-179843  [001] b..11 33223.507781: bpf_trace_printk: [O] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656155, a: 2040780433, f: A
           curl-179843  [001] ..s21 33223.507786: bpf_trace_printk: [I] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656155, a: 2040780433, f: A

           curl-179843  [001] b.s31 33223.507792: bpf_trace_printk: [O] ifx: 1, sip: 127.0.0.1, sport: 8080, dip: 127.0.0.1, dport: 8971, s: 2040780433, a: 31656232, f: A
           curl-179843  [001] ..s21 33223.507795: bpf_trace_printk: [I] ifx: 1, sip: 127.0.0.1, sport: 8080, dip: 127.0.0.1, dport: 8971, s: 2040780433, a: 31656232, f: A
    docker-proxy-174167  [010] b..11 33223.509024: bpf_trace_printk: [O] ifx: 1, sip: 127.0.0.1, sport: 8080, dip: 127.0.0.1, dport: 8971, s: 2040780433, a: 31656232, f: A
    docker-proxy-174167  [010] ..s21 33223.509060: bpf_trace_printk: [I] ifx: 1, sip: 127.0.0.1, sport: 8080, dip: 127.0.0.1, dport: 8971, s: 2040780433, a: 31656232, f: A

    docker-proxy-174167  [010] b.s31 33223.509118: bpf_trace_printk: [O] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656232, a: 2040781286, f: A
    docker-proxy-174167  [010] ..s21 33223.509136: bpf_trace_printk: [I] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656232, a: 2040781286, f: A

FOUR WAY HANDSHAKE (togheter with the FIN the client sends also the ACK for the last received data)
            curl-179843  [013] b..11 33223.510259: bpf_trace_printk: [O] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656232, a: 2040781286, f: F+A
            curl-179843  [013] ..s21 33223.510276: bpf_trace_printk: [I] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656232, a: 2040781286, f: F+A

    docker-proxy-174167  [008] b..11 33223.510486: bpf_trace_printk: [O] ifx: 1, sip: 127.0.0.1, sport: 8080, dip: 127.0.0.1, dport: 8971, s: 2040781286, a: 31656233, f: F+A
    docker-proxy-174167  [008] ..s21 33223.510502: bpf_trace_printk: [I] ifx: 1, sip: 127.0.0.1, sport: 8080, dip: 127.0.0.1, dport: 8971, s: 2040781286, a: 31656233, f: F+A

    docker-proxy-174167  [008] b.s31 33223.510518: bpf_trace_printk: [O] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656233, a: 2040781287, f: A
    docker-proxy-174167  [008] ..s21 33223.510535: bpf_trace_printk: [I] ifx: 1, sip: 127.0.0.1, sport: 8971, dip: 127.0.0.1, dport: 8080, s: 31656233, a: 2040781287, f: A
```
