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
  -p, --pre-access <PRE_ACCESS>      Make `access` system call prior to executing shellcode
  -o, --post-access <POST_ACCESS>    Make `access` system call after having executed shellcode
  -h, --help                         Print help
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

```console
$ ( shellcraft amd64.linux.findpeer ; shellcraft amd64.linux.dupio rdi ; shellcraft amd64.linux.echo 'Hello, World
> ' ; shellcraft amd64.linux.exit 0 ) >findpeer
$ nc localhost 8899 <findpeer
Hello, World!
```

The server will exit after first connection unless `--fork` has been specified.

You can also provide the mutually exclusive `--ipv4` and `--ipv6` options to specify which protocol to use.

### Security

Executing shellcode from an untrusted source is dangerous so you can drop privileges and change root prior to executing shellcode:

```console
$ mkdir empty
$ sudo ./target/debug/run_shellcode --chroot empty --uid 1000 --gid 1000 8899
```

### Shellcode debugging

If you `strace` the `run_shellcode` process in order to debug your shellcode you might want to use the `--pre-access` and `--post-access` options
in order to mark when your shellcode begins or ends:

```console
$ (shellcraft amd64.linux.echo 'Hello, World!
' ; ( echo -e 'add rsp, 16\nret' | asm -c amd64 )) >hello_ret
$ strace ./target/debug/run_shellcode --pre-access '===== Shellcode starts' --post-access '==== Shellcode ends' hello_ret
....
close(3)                                = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7b3ab6335000
mprotect(0x7b3ab6335000, 4096, PROT_READ|PROT_EXEC) = 0
access("===== Shellcode starts", F_OK)  = -1 ENOENT (No such file or directory)
write(1, "Hello, World!\n", 14Hello, World!
)         = 14
access("==== Shellcode ends", F_OK)     = -1 ENOENT (No such file or directory)
sigaltstack({ss_sp=NULL, ss_flags=SS_DISABLE, ss_size=8192}, NULL) = 0
munmap(0x7b3ab6336000, 12288)           = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

That makes it much easier to spot your shellcode execution.

You can also place a breakpoint before your shellcode on certain architectures (`x86` and `x86_64`):

```console
$ gdb -q -iex 'set debuginfod enabled off' ./target/release/run_shellcode -ex 'r -b hello'
Reading symbols from ./target/release/run_shellcode...
(No debugging symbols found in ./target/release/run_shellcode)
Starting program: /home/robert/code/RunShellcodeRust/target/release/run_shellcode -b hello
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGTRAP, Trace/breakpoint trap.
0x00007ffff7fb7001 in ?? ()
(gdb) x/18i $rip
=> 0x7ffff7fb7001:      movabs rax,0x101010101010101
   0x7ffff7fb700b:      push   rax
   0x7ffff7fb700c:      movabs rax,0x1010b20656d736e
   0x7ffff7fb7016:      xor    QWORD PTR [rsp],rax
   0x7ffff7fb701a:      movabs rax,0x57202c6f6c6c6548
   0x7ffff7fb7024:      push   rax
   0x7ffff7fb7025:      push   0x1
   0x7ffff7fb7027:      pop    rax
   0x7ffff7fb7028:      push   0x1
   0x7ffff7fb702a:      pop    rdi
   0x7ffff7fb702b:      push   0xe
   0x7ffff7fb702d:      pop    rdx
   0x7ffff7fb702e:      mov    rsi,rsp
   0x7ffff7fb7031:      syscall
   0x7ffff7fb7033:      xor    edi,edi
   0x7ffff7fb7035:      push   0x3c
   0x7ffff7fb7037:      pop    rax
   0x7ffff7fb7038:      syscall
(gdb)
```

Note that this moves your shellcode by one byte.
