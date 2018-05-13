---
title: "Code Disassembly with Pydasm"
excerpt: "How to disassemble x86 code with Pydasm on Windows."
tags:
  - x86
  - python
  - rce
  - pydasm
---

---
In this post, I would like to show you how to use a famous Python module named **pydasm**, a python wrapper for [libdasm](https://github.com/axcheron/libdasm). It attempts to capture all the functionality of libdasm and bring its versatility to Python.

**libdasm** is a C-library that tries to provide simple and convenient way to disassemble Intel x86 raw opcode bytes (machine code). It can parse and print out opcodes in *AT&T* and *Intel* syntax.

Nowadays, it exists more powerfull disassembler like [Capstone Engine](http://www.capstone-engine.org), but as I often use [pydbg](https://github.com/axcheron/pydbg), a pure-python win32 debugger interface, I still use pydasm for some of my projects.

## Installation

We will do our tests on a Windows based machine (I will use Windows 10). To prepare the environment you need to install the following dependencies:

* [Python 2.7](https://www.python.org/downloads/)
* [Microsoft Visual C++ Compiler for Python 2.7](https://www.microsoft.com/en-us/download/details.aspx?id=44266)
* [pydasm](https://github.com/axcheron/pydasm)

**Note:** Be sure to add *python.exe* to your environment **PATH**. It can be automatically done during the installation of Python.
{: .notice--info}

```bash
$ cd pydasm-master

$ python setup.py install

running install
running bdist_egg
running egg_info
creating pydasm.egg-info

...

creating 'dist\pydasm-1.5-py2.7-win32.egg' and adding 'build\bdist.win32\egg' to it
removing 'build\bdist.win32\egg' (and everything under it)
Processing pydasm-1.5-py2.7-win32.egg
Copying pydasm-1.5-py2.7-win32.egg to c:\python27\lib\site-packages
Adding pydasm 1.5 to easy-install.pth file

Installed c:\python27\lib\site-packages\pydasm-1.5-py2.7-win32.egg
Processing dependencies for pydasm==1.5
Finished processing dependencies for pydasm==1.5
``` 

Now, you just have to copy `pydasm.pyd` from `C:\Users\User\Desktop\pydasm-master\build\lib.win32-2.7\` into `C:\Python27\DLLs`.

## Exported Methods

**Pydasm** come with some exported methods helping us to disassemble binary files. If you look at the source code, as a wrapper, *pydasm* come with some python counterpart of libdasm's, including :

* `get_instruction()`
* `get_instruction_string()`
* `get_mnemonic_string()`
* `get_operand_string()`
* `get_register_type()`

Let's take a look at each of them...

### About get_instruction()

This method is the Python counterpart of libdasm's `get_instruction()`. Here is the prototype of the method: 

```python
def pydasm_get_instruction(data, mode)
```

It decodes an instruction from the given buffer. It takes 2 arguments: 

* `data`, a string containing the data to disassemble.
* `mode`, either *MODE_16* or *MODE_32*.

It returns an `INSTRUCTION` object or `None` if the instruction can't be disassembled. I won't explain the content of the `INSTRUCTION` object, but for your information, here is the structure definition:

```c
typedef struct _INSTRUCTION {
	int length;		// Instruction length
	enum Instruction type;	// Instruction type
	enum Mode mode;		// Addressing mode
	BYTE opcode;		// Actual opcode
	BYTE modrm;		// MODRM byte
	BYTE sib;		// SIB byte
	int modrm_offset;	// MODRM byte offset
	int extindex;		// Extension table index
	int fpuindex;		// FPU table index
	int dispbytes;		// Displacement bytes (0 = no displacement)
	int immbytes;		// Immediate bytes (0 = no immediate)
	int sectionbytes;	// Section prefix bytes (0 = no section prefix)
	OPERAND op1;		// First operand (if any)
	OPERAND op2;		// Second operand (if any)
	OPERAND op3;		// Additional operand (if any)
	PINST ptr;		// Pointer to instruction table
	int flags;		// Instruction flags
	short eflags_affected;	// Process eflags affected
	short eflags_used;      // Processor eflags used by this instruction
	int iop_written;	// mask of affected implied registers (written)
	int iop_read;		// mask of affected implied registers (read)
} INSTRUCTION, *PINSTRUCTION;
```

**Note:** For more details about the `INSTRUCTION`, I suggest you read the source code of *pydasm* to get a full understanding of how it works and how you can use it in your code.
{: .notice--info}

### About get_instruction_string()

This method is the Python counterpart of libdasm's `get_instruction_string()`. Here is the prototype of the method: 

```python
def pydasm_get_instruction(INSTRUCTION, format, offset)
```

It decodes an instruction from the given buffer. It takes 3 arguments: 

* `INSTRUCTION`, the `INSTRUCTION` object.
* `format`, the format, *FORMAT_INTEL* or *FORMAT_ATT*, depending on how you want to display the code.
* `offest`, the base address of the executable.

It returns a string representation of the disassembled instruction or zero if there is nothing to desassemble.

**Note:** Although Intel is the standard assembly syntax on the x86 platform and is generally thought to be nicer than AT&T, there is still good reason to learn AT&T as the `gcc` compiler emits code in this syntax. If you don't know what to choose, I suggest you to select *FORMAT_INTEL*.
{: .notice--info}

Note that the `offest` parameter can be set at zero by default. Here is the difference if you specify the base address of the executable. Here is an example With **zero** as parameter:

```nasm
push byte 0x60
push dword 0x46e070
call 0x210e			; RVA
mov edi,0x94
mov eax,edi
call 0xffffddee		; RVA
```

With the **base address** as parameter:

```nasm
push byte 0x60
push dword 0x46e070
call 0x44e5f4			; VA
mov edi,0x94
mov eax,edi
call 0x44a2e0			; VA
```

As you can see, if we specify a virtual address for the instruction we want to disassemble, calls and conditions will use the base address instead of the relative address you set (zero in this example).

### About get_mnemonic_string()

This method is the Python counterpart of libdasm's `get_mnemonic_string()`. Here is the prototype of the method: 

```python
def get_mnemonic_string(INSTRUCTION, format)
```

It transforms an instruction object's mnemonic into its string representation. It takes 2 arguments: 

* `INSTRUCTION`, the `INSTRUCTION` object.
* `format`, the format, *FORMAT_INTEL* or *FORMAT_ATT*, depending on how you want to display the code.

It returns a string representation of the mnemonic.

### About get_operand_string()

This method is the Python counterpart of libdasm's `get_operand_string()`. Here is the prototype of the method: 

```python
def get_operand_string(INSTRUCTION, operand, format, offset)
```

It transform an instruction object's operand into its string representation. It takes 4 arguments: 

* `INSTRUCTION`, the `INSTRUCTION` object.
* `operand`, the operand index (0,1,2).
* `format`, the format, *FORMAT_INTEL* or *FORMAT_ATT*, depending on how you want to display the code.
* `offest`, the base address of the executable.

It returns a string representation of the disassembled operand.

### About get_register_type()

This method is the Python counterpart of libdasm's `get_register_type()`. Here is the prototype of the method: 

```python
def get_register_type(OPERAND)
```

It transforms an instruction object's mnemonic into its string representation. It takes 1 argument: 

* `OPERAND`, the `OPERAND` object.

It returns a Long representing the type of the register. I won't explain the content of the `OPERAND` object, but for your information, here is the structure definition:

```c
typedef struct _OPERAND {
	enum Operand type;	// Operand type (register, memory, etc)
	int reg;		// Register (if any)
	int basereg;		// Base register (if any)
	int indexreg;		// Index register (if any)
	int scale;		// Scale (if any)
	int dispbytes;		// Displacement bytes (0 = no displacement)
	int dispoffset;		// Displacement value offset
	int immbytes;		// Immediate bytes (0 = no immediate)
	int immoffset;		// Immediate value offset
	int sectionbytes;	// Section prefix bytes (0 = no section prefix)
	WORD section;		// Section prefix value
	DWORD displacement;	// Displacement value
	DWORD immediate;	// Immediate value
	int flags;		// Operand flags
} OPERAND, *POPERAND;
```

## A Bit of Practice

Now we will disassemble a Windows executable (PE file format). In a PE file, the first bytes contain the structure of the file and don't represent any executable code. To disassemble the code, we need to find the *entry point* of the `.text` section. To do that I will use a python module called *pefile*.

**Note:** If you want more information about *pefile* and the Portable Executable format, I suggest you read by previous blog [post](http://breakinsecurity.com/pe-format-manipulation-with-pefile/).
{: .notice--info}

**Note:** For the tests I used **putty.exe**. [PuTTY](http://www.chiark.greenend.org.uk/~sgtatham/putty/) is a free implementation of SSH and Telnet for Windows, but you can use any executable or binary file.
{: .notice--info}

```python
import pydasm
import pefile

exe_path = "putty.exe"

# Store the file in a variable
fd = open(exe_path, 'rb')
data = fd.read()
fd.close()

# Get the EP, raw size and virtual address of the code
pe = pefile.PE(exe_path)
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
raw_size = pe.sections[0].SizeOfRawData
ep_va = ep + pe.OPTIONAL_HEADER.ImageBase

print "[*] Entry Point: " + hex(ep)
print "[*] Raw Size: " + hex(raw_size)
print "[*] EP VA: " + hex(ep_va)

# Start disassembly at the EP
offset = ep

# Loop until the end of the .text section
while offset < (offset + raw_size):
    # Get the first instruction
    i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
    # Print a string representation if the instruction
    print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_va + offset)
    # Go to the next instruction
    offset += i.length
```

In this code sample, we fill a variable with the content of the binary and get the address of the code we want to disassemble. The we call `get_instruction()` by passing the offset of the code and ask to use the 32 bit mode (its a 32 bit binary). The we call `get_instruction_string()` by passing the `INSTRUCTION` structure, format and the virtal address. You could use zero as the offset, but a real disassembler would show you the virtal address. Then we loop until the end of the section by incrementing the offset.

Here is a sample from the output:

```nasm
[*] Entry Point: 0x550f0
[*] Raw Size: 0x5c000
[*] EP VA: 0x4550f0

push byte 0x60
push dword 0x478108
call 0x4ac2f4
mov edi,0x94
mov eax,edi
call 0x4a9cb0
mov [ebp-0x18],esp
mov esi,esp
...
```

## Reading a Shellcode

You can also read pure binary data, like a shellcode. It could be useful when you download a random shellcode from Internet if you don't know what it really does (think about `rm -rf /` shellcode...).

```python
import pydasm

# windows/messagebox - 281 bytes
# http://www.metasploit.com
# VERBOSE=false, EXITFUNC=process, TITLE=BreakInSecurity,
# TEXT=Hello, I'm in ur code, ICON=INFORMATION

shellcode = ("\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
             "\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
             "\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
             "\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
             "\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
             "\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
             "\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
             "\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
             "\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
             "\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
             "\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
             "\x32\x2e\x64\x68\x75\x73\x65\x72\x88\x5c\x24\x0a\x89\xe6\x56"
             "\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24\x52"
             "\xe8\x61\xff\xff\xff\x68\x69\x74\x79\x58\x68\x65\x63\x75\x72"
             "\x68\x6b\x49\x6e\x53\x68\x42\x72\x65\x61\x31\xdb\x88\x5c\x24"
             "\x0f\x89\xe3\x68\x65\x58\x20\x20\x68\x20\x63\x6f\x64\x68\x6e"
             "\x20\x75\x72\x68\x27\x6d\x20\x69\x68\x6f\x2c\x20\x49\x68\x48"
             "\x65\x6c\x6c\x31\xc9\x88\x4c\x24\x15\x89\xe1\x31\xd2\x6a\x40"
             "\x53\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08")

format = pydasm.FORMAT_INTEL
mode = pydasm.MODE_32
offset = 0

while offset < len(shellcode):
    instruction = pydasm.get_instruction(shellcode[offset:], mode)
    print pydasm.get_instruction_string(instruction, format, 0)
    if not instruction:
        offset += 1
        continue

    offset += instruction.length
```

**Output**

```nasm
fldpi 
wait 
fstenv [esp-0xc]
xor edx,edx
mov dl,0x77
xor ecx,ecx
mov esi,fs:[ecx+0x30]
mov esi,[esi+0xc]
mov esi,[esi+0x1c]
...
```

## Conclusion

We are done with this quick introduction to *pydasm*, I hope it will be useful for you next projects. Have fun !

## Resources

* [libdasm export on GitHub](https://github.com/axcheron/libdasm)

