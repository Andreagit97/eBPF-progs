# eBPF progs

The idea is to use these programs to easily debug eBPF issues on machines that only have a limited set of tools installed.
In many examples `git` is the only tool required since we provide a static binary already compiled called `main`.
Ideally having a C compiler and go installed would be great, but in some environments this is not possible.

## Build progs

If you have clang and go installed you can build the programs yourself.

```bash
go generate ./...
go build -o main .
```
