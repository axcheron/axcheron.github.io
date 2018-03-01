---
title: "Lab1B Write-up"
permalink: /writeups/mbe/lab1b/
excerpt: "Write-up for Lab1B."
---

---
**Lab1B** is quite similar to the previous challenge, but our input will be modified processed in a different manner. Log into the Lab1B with the password we found previously **lab1B:n0_str1ngs_n0_pr0bl3m** and go to the challenges folder: `cd /levels/lab01/`.

Let's try to execute the program:

```shell
lab1B@warzone:/levels/lab01$ ./lab1B
.---------------------------.
|-- RPISEC - CrackMe v2.0 --|
'---------------------------'

Password: TestMe!

Invalid Password!
```

## Binary Analysis

This time, the code is composed of 3 routines (**main**, **test** and **decrypt**). Let's reverse the first one.

### Main

```nasm
lab1B@warzone:/levels/lab01$ gdb lab1B
gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x08048be4 <+0>:	push   ebp
   0x08048be5 <+1>:	mov    ebp,esp
   0x08048be7 <+3>:	and    esp,0xfffffff0
   0x08048bea <+6>:	sub    esp,0x20
   0x08048bed <+9>:	push   eax
   0x08048bee <+10>:	xor    eax,eax
   0x08048bf0 <+12>:	je     0x8048bf5 <main+17>
   0x08048bf2 <+14>:	add    esp,0x4
   0x08048bf5 <+17>:	pop    eax
   0x08048bf6 <+18>:	mov    DWORD PTR [esp],0x0
   0x08048bfd <+25>:	call   0x80487b0 <time@plt>
   0x08048c02 <+30>:	mov    DWORD PTR [esp],eax
   0x08048c05 <+33>:	call   0x8048800 <srand@plt>
   0x08048c0a <+38>:	mov    DWORD PTR [esp],0x8048d88
   0x08048c11 <+45>:	call   0x80487d0 <puts@plt>
   0x08048c16 <+50>:	mov    DWORD PTR [esp],0x8048da6
   0x08048c1d <+57>:	call   0x80487d0 <puts@plt>
   0x08048c22 <+62>:	mov    DWORD PTR [esp],0x8048dc4
   0x08048c29 <+69>:	call   0x80487d0 <puts@plt>
   0x08048c2e <+74>:	mov    DWORD PTR [esp],0x8048de2
   0x08048c35 <+81>:	call   0x8048780 <printf@plt>
   0x08048c3a <+86>:	lea    eax,[esp+0x1c]
   0x08048c3e <+90>:	mov    DWORD PTR [esp+0x4],eax
   0x08048c42 <+94>:	mov    DWORD PTR [esp],0x8048dee ; format = "%d"
   0x08048c49 <+101>:	call   0x8048840 <__isoc99_scanf@plt>
   0x08048c4e <+106>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048c52 <+110>:	mov    DWORD PTR [esp+0x4],0x1337d00d
   0x08048c5a <+118>:	mov    DWORD PTR [esp],eax ; ptr to user input
   0x08048c5d <+121>:	call   0x8048a74 <test>
   0x08048c62 <+126>:	mov    eax,0x0
   0x08048c67 <+131>:	leave  
   0x08048c68 <+132>:	ret    
End of assembler dump.
```

### Test

```nasm
gdb-peda$ disassemble test
Dump of assembler code for function test:
   0x08048a74 <+0>:	push   ebp
   0x08048a75 <+1>:	mov    ebp,esp
   0x08048a77 <+3>:	sub    esp,0x28
   0x08048a7a <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048a7d <+9>:	mov    edx,DWORD PTR [ebp+0xc]
   0x08048a80 <+12>:	sub    edx,eax
   0x08048a82 <+14>:	mov    eax,edx
   0x08048a84 <+16>:	mov    DWORD PTR [ebp-0xc],eax
   0x08048a87 <+19>:	cmp    DWORD PTR [ebp-0xc],0x15
   0x08048a8b <+23>:	ja     0x8048bd5 <test+353>
   0x08048a91 <+29>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048a94 <+32>:	shl    eax,0x2
   0x08048a97 <+35>:	add    eax,0x8048d30
   0x08048a9c <+40>:	mov    eax,DWORD PTR [eax]
   0x08048a9e <+42>:	jmp    eax
   0x08048aa0 <+44>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048aa3 <+47>:	mov    DWORD PTR [esp],eax
   0x08048aa6 <+50>:	call   0x80489b7 <decrypt>
   0x08048aab <+55>:	jmp    0x8048be2 <test+366>
   0x08048ab0 <+60>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048ab3 <+63>:	mov    DWORD PTR [esp],eax
   0x08048ab6 <+66>:	call   0x80489b7 <decrypt>
   0x08048abb <+71>:	jmp    0x8048be2 <test+366>
   0x08048ac0 <+76>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048ac3 <+79>:	mov    DWORD PTR [esp],eax
   0x08048ac6 <+82>:	call   0x80489b7 <decrypt>
   0x08048acb <+87>:	jmp    0x8048be2 <test+366>
   0x08048ad0 <+92>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048ad3 <+95>:	mov    DWORD PTR [esp],eax
   0x08048ad6 <+98>:	call   0x80489b7 <decrypt>
   0x08048adb <+103>:	jmp    0x8048be2 <test+366>
   0x08048ae0 <+108>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048ae3 <+111>:	mov    DWORD PTR [esp],eax
   0x08048ae6 <+114>:	call   0x80489b7 <decrypt>
   0x08048aeb <+119>:	jmp    0x8048be2 <test+366>
   0x08048af0 <+124>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048af3 <+127>:	mov    DWORD PTR [esp],eax
   0x08048af6 <+130>:	call   0x80489b7 <decrypt>
   0x08048afb <+135>:	jmp    0x8048be2 <test+366>
   0x08048b00 <+140>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b03 <+143>:	mov    DWORD PTR [esp],eax
   0x08048b06 <+146>:	call   0x80489b7 <decrypt>
   0x08048b0b <+151>:	jmp    0x8048be2 <test+366>
   0x08048b10 <+156>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b13 <+159>:	mov    DWORD PTR [esp],eax
   0x08048b16 <+162>:	call   0x80489b7 <decrypt>
   0x08048b1b <+167>:	jmp    0x8048be2 <test+366>
   0x08048b20 <+172>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b23 <+175>:	mov    DWORD PTR [esp],eax
   0x08048b26 <+178>:	call   0x80489b7 <decrypt>
   0x08048b2b <+183>:	jmp    0x8048be2 <test+366>
   0x08048b30 <+188>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b33 <+191>:	mov    DWORD PTR [esp],eax
   0x08048b36 <+194>:	call   0x80489b7 <decrypt>
   0x08048b3b <+199>:	jmp    0x8048be2 <test+366>
   0x08048b40 <+204>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b43 <+207>:	mov    DWORD PTR [esp],eax
   0x08048b46 <+210>:	call   0x80489b7 <decrypt>
   0x08048b4b <+215>:	jmp    0x8048be2 <test+366>
   0x08048b50 <+220>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b53 <+223>:	mov    DWORD PTR [esp],eax
   0x08048b56 <+226>:	call   0x80489b7 <decrypt>
   0x08048b5b <+231>:	jmp    0x8048be2 <test+366>
   0x08048b60 <+236>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b63 <+239>:	mov    DWORD PTR [esp],eax
   0x08048b66 <+242>:	call   0x80489b7 <decrypt>
   0x08048b6b <+247>:	jmp    0x8048be2 <test+366>
   0x08048b6d <+249>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b70 <+252>:	mov    DWORD PTR [esp],eax
   0x08048b73 <+255>:	call   0x80489b7 <decrypt>
   0x08048b78 <+260>:	jmp    0x8048be2 <test+366>
   0x08048b7a <+262>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b7d <+265>:	mov    DWORD PTR [esp],eax
   0x08048b80 <+268>:	call   0x80489b7 <decrypt>
   0x08048b85 <+273>:	jmp    0x8048be2 <test+366>
   0x08048b87 <+275>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b8a <+278>:	mov    DWORD PTR [esp],eax
   0x08048b8d <+281>:	call   0x80489b7 <decrypt>
   0x08048b92 <+286>:	jmp    0x8048be2 <test+366>
   0x08048b94 <+288>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b97 <+291>:	mov    DWORD PTR [esp],eax
   0x08048b9a <+294>:	call   0x80489b7 <decrypt>
   0x08048b9f <+299>:	jmp    0x8048be2 <test+366>
   0x08048ba1 <+301>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048ba4 <+304>:	mov    DWORD PTR [esp],eax
   0x08048ba7 <+307>:	call   0x80489b7 <decrypt>
   0x08048bac <+312>:	jmp    0x8048be2 <test+366>
   0x08048bae <+314>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048bb1 <+317>:	mov    DWORD PTR [esp],eax
   0x08048bb4 <+320>:	call   0x80489b7 <decrypt>
   0x08048bb9 <+325>:	jmp    0x8048be2 <test+366>
   0x08048bbb <+327>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048bbe <+330>:	mov    DWORD PTR [esp],eax
   0x08048bc1 <+333>:	call   0x80489b7 <decrypt>
   0x08048bc6 <+338>:	jmp    0x8048be2 <test+366>
   0x08048bc8 <+340>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048bcb <+343>:	mov    DWORD PTR [esp],eax
   0x08048bce <+346>:	call   0x80489b7 <decrypt>
   0x08048bd3 <+351>:	jmp    0x8048be2 <test+366>
   0x08048bd5 <+353>:	call   0x8048830 <rand@plt>
   0x08048bda <+358>:	mov    DWORD PTR [esp],eax
   0x08048bdd <+361>:	call   0x80489b7 <decrypt>
   0x08048be2 <+366>:	leave  
   0x08048be3 <+367>:	ret    
End of assembler dump.
```

### Decrypt


```nasm
gdb-peda$ disassemble decrypt 
Dump of assembler code for function decrypt:
   0x080489b7 <+0>:	push   ebp
   0x080489b8 <+1>:	mov    ebp,esp
   0x080489ba <+3>:	sub    esp,0x38
   0x080489bd <+6>:	mov    eax,gs:0x14
   0x080489c3 <+12>:	mov    DWORD PTR [ebp-0xc],eax
   0x080489c6 <+15>:	xor    eax,eax
   0x080489c8 <+17>:	mov    DWORD PTR [ebp-0x1d],0x757c7d51
   0x080489cf <+24>:	mov    DWORD PTR [ebp-0x19],0x67667360
   0x080489d6 <+31>:	mov    DWORD PTR [ebp-0x15],0x7b66737e
   0x080489dd <+38>:	mov    DWORD PTR [ebp-0x11],0x33617c7d
   0x080489e4 <+45>:	mov    BYTE PTR [ebp-0xd],0x0
   0x080489e8 <+49>:	push   eax
   0x080489e9 <+50>:	xor    eax,eax
   0x080489eb <+52>:	je     0x80489f0 <decrypt+57>
   0x080489ed <+54>:	add    esp,0x4
   0x080489f0 <+57>:	pop    eax
   0x080489f1 <+58>:	lea    eax,[ebp-0x1d]
   0x080489f4 <+61>:	mov    DWORD PTR [esp],eax
   0x080489f7 <+64>:	call   0x8048810 <strlen@plt>
   0x080489fc <+69>:	mov    DWORD PTR [ebp-0x24],eax
   0x080489ff <+72>:	mov    DWORD PTR [ebp-0x28],0x0
   0x08048a06 <+79>:	jmp    0x8048a28 <decrypt+113>
   0x08048a08 <+81>:	lea    edx,[ebp-0x1d]
   0x08048a0b <+84>:	mov    eax,DWORD PTR [ebp-0x28]
   0x08048a0e <+87>:	add    eax,edx
   0x08048a10 <+89>:	movzx  eax,BYTE PTR [eax]
   0x08048a13 <+92>:	mov    edx,eax
   0x08048a15 <+94>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048a18 <+97>:	xor    eax,edx
   0x08048a1a <+99>:	lea    ecx,[ebp-0x1d]
   0x08048a1d <+102>:	mov    edx,DWORD PTR [ebp-0x28]
   0x08048a20 <+105>:	add    edx,ecx
   0x08048a22 <+107>:	mov    BYTE PTR [edx],al
   0x08048a24 <+109>:	add    DWORD PTR [ebp-0x28],0x1
   0x08048a28 <+113>:	mov    eax,DWORD PTR [ebp-0x28]
   0x08048a2b <+116>:	cmp    eax,DWORD PTR [ebp-0x24]
   0x08048a2e <+119>:	jb     0x8048a08 <decrypt+81>
   0x08048a30 <+121>:	mov    DWORD PTR [esp+0x4],0x8048d03
   0x08048a38 <+129>:	lea    eax,[ebp-0x1d]
   0x08048a3b <+132>:	mov    DWORD PTR [esp],eax
   0x08048a3e <+135>:	call   0x8048770 <strcmp@plt>
   0x08048a43 <+140>:	test   eax,eax
   0x08048a45 <+142>:	jne    0x8048a55 <decrypt+158>
   0x08048a47 <+144>:	mov    DWORD PTR [esp],0x8048d14
   0x08048a4e <+151>:	call   0x80487e0 <system@plt>
   0x08048a53 <+156>:	jmp    0x8048a61 <decrypt+170>
   0x08048a55 <+158>:	mov    DWORD PTR [esp],0x8048d1c
   0x08048a5c <+165>:	call   0x80487d0 <puts@plt>
   0x08048a61 <+170>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048a64 <+173>:	xor    eax,DWORD PTR gs:0x14
   0x08048a6b <+180>:	je     0x8048a72 <decrypt+187>
   0x08048a6d <+182>:	call   0x80487c0 <__stack_chk_fail@plt>
   0x08048a72 <+187>:	leave  
   0x08048a73 <+188>:	ret    
End of assembler dump.
```


## Solution

