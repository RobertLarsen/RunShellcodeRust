RunShellcode Rust
=================

This is just a rewrite of my previous shellcode runner which was written in C.

## Usage

```console
$ ./target/debug/run_shellcode --help
Run shellcode from standard in, a TCP server or from a file

Usage: run_shellcode [OPTIONS] [SOURCE]

Arguments:
  [SOURCE]  Source of shellcode. Standard in if absent or the string '-', TCP port if integer, otherwise path to file

Options:
  -4, --ipv4                         Use IPv4 for the TCP server
  -6, --ipv6                         Use IPv6 for the TCP server
  -f, --fork                         Fork the TCP server for each client
  -t, --tcp-timeout <TCP_TIMEOUT>    Timeout in milliseconds for reading shellcode on network`` [default: 100]
  -u, --uid <UID>                    Change user id to this before executing shellcode
  -g, --gid <GID>                    Change group id to this before executing shellcode
  -c, --chroot <ROOT PATH>           Change root directory prior to executing the shellcode
  -w, --writable                     Mark shellcode memory as writable
  -l, --load-address <LOAD_ADDRESS>  Load shellcode at this address
  -h, --help                         Print hel
```

### From a file

```console
$ ( shellcraft amd64.linux.echo 'Hello, World!
> ' ; shellcraft amd64.linux.exit 0 ) >hello
$ ./target/debug/run_shellcode hello
Hello, World!
```

### From standard in

```console
$ cat hello | ./target/debug/run_shellcode
Hello, World!
```

or

```console
$ ./target/debug/run_shellcode <hello
Hello, World!
```

### From a TCP stream

In one terminal:

```console
$ ./target/debug/run_shellcode 8899
```

...and in another:

```
$ ( shellcraft amd64.linux.findpeer ; shellcraft amd64.linux.dupio rdi ; shellcraft amd64.linux.echo 'Hello, World
> ' ; shellcraft amd64.linux.exit 0 ) >findpeer
$ nc localhost 8899 <findpeer
Hello, World!
```

The server will exit after first connection unless `--fork` has been specified.

You can also provide the mutually exclusive `--ipv4` and `--ipv6` options to specify which protocol to use.

### Security

Executing shellcode from an untrusted source is dangerous so you can drop privileges and change root prior to executing shellcode:

```
$ mkdir empty
$ sudo ./target/debug/run_shellcode --chroot empty --uid 1000 --gid 1000 8899
```
