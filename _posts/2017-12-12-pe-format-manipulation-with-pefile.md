---
title: "PE Format Manipulation with PEFile"
excerpt: "How to read and modify Portable Executable (PE) format with Python and PEFile."
tags:
  - pe
  - windows
  - python
---

---
{% include toc icon="cog" title="PE Format Manipulation" %}
A long time ago, I wrote an article about how to use the **pefile** module to analyze the *Portable Executable* file format, but this post does not exist anymore. As I use this module quite often, I decided to rewrite it. This module now supports Python 3 and some bugs have been fixed.

**pefile** is a Python module to read and work with PE (Portable Executable) files, it was developed by [Ero Carrera](https://github.com/erocarrera). This module is multi-platform and is able to parse and edit Portable Executable files. Most of the information contained in the PE headers is accessible as well as all sections' details and their data. To fully appreciate this post it is required to have some basic understanding of the layout of a PE file.

*pefile* offers many features, including:

* Inspecting headers
* Analysis of sections' data
* Retrieving embedded data
* Reading strings from the resources
* Warnings for suspicious and malformed values
* Support to write to some of the fields and to other parts of the PE
* Packer detection with PEiD’s signatures
* PEiD signature generation

Also, the [project repository](https://github.com/erocarrera/pefile/blob/wiki/UsageExamples.md) includes some usage examples if you want more details.

## Installation

This procedure has been tested on the last version of Microsoft Windows 10, but it should work on previous version. First, be sure to prepare your environment :

* Install [Python 3](https://www.python.org/downloads/)
* Download or clone *pefile* [https://github.com/erocarrera/pefile.git](https://github.com/erocarrera/pefile.git)

Run *cmd.exe* as administrator and type the following commands:

```bash
# If you have Git for Windows installed
$ git clone https://github.com/erocarrera/pefile.git

$ cd pefile
$ pip install -r requirements.txt
$ python setup.py install
```

Then try to import *pefile* to check if the installation was successful:

```bash
$ python

Python 3.5.2 (v3.5.2:4def2a2901a5, Jun 25 2016, 22:01:18) [MSC v.1900 32 bit (Intel)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import pefile
>>>
```

If you get no error, you are ready to go !

**Note:** For the tests I used **putty.exe**. [PuTTY](http://www.chiark.greenend.org.uk/~sgtatham/putty/) is a free implementation of SSH and Telnet for Windows, but you can use any executable.
{: .notice--info}

## Loading a file

Getting started with *pefile* is fairly simple. First you need to import the module in your code and then the `PE` class using the executable path as a parameter. You can also pass other parameters, including:

* `name`
* `data`
* `fast_load`

`name` is the default parameter and should contains the executable path.

```python
import pefile

exe_path = "c:\putty.exe"

try:
    pe = pefile.PE(exe_path)
    # This is also a valid function call
    # pe = pefile.PE(name=exe_path)
except OSError as e:
    print(e)
except pefile.PEFormatError as e:
    print("[-] PEFormatError: %s" % e.value)
```

It's also possible to parse raw PE data by using `data` as parameter.

```python
import pefile
import mmap

exe_path = "c:\Windows\System32\calc.exe"

# Map the executable in memory
fd = open(exe_path, 'rb')
pe_data = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)

# Parse the data contained in the buffer
pe = pefile.PE(data=pe_data)
```

If your file is quite big, setting the `fast_load` argument to **True** will prevent parsing the directories. It will speed up the loading if you don't need information from the data directories. Only the basic headers information will be available in the attributes:

* `DOS_HEADER`
* `NT_HEADERS`
* `FILE_HEADER`
* `OPTIONAL_HEADER`

If you change your mind, you can always load the missing data by using the `full_load()` method at a later stage.

```python
import pefile

exe_path = "c:\putty.exe"

pe = pefile.PE(exe_path, fast_load=True)

# Then you can call the following method later in your code
pe.full_load()
```

## Reading the Header Members

Once the executable is successfully parsed, the data is readily available as attributes of the PE instance. Let's read the following attributes:

* `e_magic` or *IMAGE_DOS_HEADER*. It should be equal to `0x5A4D` (MZ)
* `signature` or *IMAGE_NT_HEADERS*. It should be equal to `0x4550` (PE)

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

print("[*] e_magic value: %s" % hex(pe.DOS_HEADER.e_magic))
print("[*] Signature value: %s" % hex(pe.NT_HEADERS.Signature))
```

**Output**

```bash
[*] e_magic value: 0x5a4d
[*] Signature value: 0x4550
```

If you want to enemuerate each members of a specific structure, like *DOS_HEADER*, it can easily be done by using a `for` loop.

**Note:** The DOS header can be found starting at offset zero in all Portable Executable files. Its main objective is to indicate the offset of the main headers containing the actual information about the PE file, the **NT headers**. The offset where to find those headers is stored in the *e_lfanew* member.
{: .notice--info}

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

print("[*] Listing DOS_HEADER fields...")
for keys in pe.DOS_HEADER.__keys__:
	for field in keys:
		print('\t' + field)
```

**Output**

```bash
[*] Listing DOS_HEADER fields...
	e_magic
	e_cblp
	e_cp
	e_crlc
	...
	e_res2
	e_lfanew
```

You can also diplay the full content of a structure by using the `dump()` method. It will returns a string representation of the structure.

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

for field in pe.DOS_HEADER.dump():
    print(field)
```

**Output**

```bash
[IMAGE_DOS_HEADER]
0x0        0x0   e_magic:                       0x5A4D    
0x2        0x2   e_cblp:                        0x90      
0x4        0x4   e_cp:                          0x3       
0x6        0x6   e_crlc:                        0x0       
0x8        0x8   e_cparhdr:                     0x4       
...
0x28       0x28  e_res2:                        
0x3C       0x3C  e_lfanew:                      0x100    
```

In this output, the first filed is the offset related to the executable and the second field is the offset related to the structure. As the DOS header is the first structure of the executable, those values are equal.

## Data Directories

Now, we will list the Data Directories. Those directories contains address/size pairs for special tables that are found in the image file and are used by the operating system (for example, the import table and the export table). We can find the number of Data Directories in `NumberOfRvaAndSizes` located in the *Optional Header* struture.

**Note** The Optional header member describes elements of the file such as the import and export directories that make possible to locate and link DLL libraries. Other entries provide structural information about the layout of the file, such as the alignment of its sections.
{: .notice--info}

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

print("[*] Number of data directories = %d" % pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    print('\t' + data_directory.name)
```

**Output**

```bash
[*] Number of data directories = 16
	IMAGE_DIRECTORY_ENTRY_EXPORT
	IMAGE_DIRECTORY_ENTRY_IMPORT
	IMAGE_DIRECTORY_ENTRY_RESOURCE
	IMAGE_DIRECTORY_ENTRY_EXCEPTION
	IMAGE_DIRECTORY_ENTRY_SECURITY
	IMAGE_DIRECTORY_ENTRY_BASERELOC
	IMAGE_DIRECTORY_ENTRY_DEBUG
	IMAGE_DIRECTORY_ENTRY_COPYRIGHT
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR
	IMAGE_DIRECTORY_ENTRY_TLS
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
	IMAGE_DIRECTORY_ENTRY_IAT
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
	IMAGE_DIRECTORY_ENTRY_RESERVED
```

You can also display the address/size pairs of each of them: 

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

for data_dir in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    print(data_dir)
```

**Output**

```bash
[IMAGE_DIRECTORY_ENTRY_EXPORT]
0x178      0x0   VirtualAddress:                0x0       
0x17C      0x4   Size:                          0x0       
[IMAGE_DIRECTORY_ENTRY_IMPORT]
0x180      0x0   VirtualAddress:                0x78918   
0x184      0x4   Size:                          0xF0      
[IMAGE_DIRECTORY_ENTRY_RESOURCE]
0x188      0x0   VirtualAddress:                0x81000   
0x18C      0x4   Size:                          0x2EC0    

...
```

## Listing the Symbols

### Imports

To list the imported DLLs by the executable, we can iterate through the data directory *DIRECTORY_ENTRY_IMPORT*

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

print("[*] Listing imported DLLs...")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print('\t' + entry.dll.decode('utf-8'))
```

**Output**

```bash
[*] Listing imported DLLs...
	ADVAPI32.dll
	COMCTL32.dll
	comdlg32.dll
	GDI32.dll
	IMM32.dll
	ole32.dll
	SHELL32.dll
	USER32.dll
	WINMM.dll
	WINSPOOL.DRV
	KERNEL32.dll
```

Then, we can list each imported function in a specific DLL, for example, **kernel32.dll**.

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode('utf-8')
    if dll_name == "KERNEL32.dll":
        print("[*] Kernel32.dll imports:")
        for func in entry.imports:
            print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))
```

**Output**

```bash
[*] Kernel32.dll imports:
	SetEnvironmentVariableA at 0x0045d130
	CompareStringW at 0x0045d134
	CompareStringA at 0x0045d138
	HeapSize at 0x0045d13c
	SetEndOfFile at 0x0045d140
	InterlockedExchange at 0x0045d144
	RtlUnwind at 0x0045d148
	SetFilePointer at 0x0045d14c
	...
```

### Exports

Similarly, the exported symbols. As **putty.exe** does not export any symbols, we will use the **kernel32.dll** in this example.

```python
import pefile

exe_path = "c:\Windows\System32\kernel32.dll"
pe = pefile.PE(exe_path)

for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name.decode('utf-8'))
```

**Output**

```bash
0x6897b184 AcquireSRWLockExclusive
0x6897b1ba AcquireSRWLockShared
0x68928660 ActivateActCtx
0x68926950 ActivateActCtxWorker
0x68917490 AddAtomA
0x68917800 AddAtomW
...
```

## Listing the Sections

Sections are added to a list accesible as the attribute sections in the PE instance. The common structure members of the section header are reachable as attributes.

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

for section in pe.sections:
    print(section.Name.decode('utf-8'))
    print("\tVirtual Address: " + hex(section.VirtualAddress))
    print("\tVirtual Size: " + hex(section.Misc_VirtualSize))
    print("\tRaw Size: " + hex(section.SizeOfRawData))
```

**Output**

```bash
.text   
	Virtual Address: 0x1000
	Virtual Size: 0x5bf81
	Raw Size: 0x5c000
.rdata  
	Virtual Address: 0x5d000
	Virtual Size: 0x1d47a
	Raw Size: 0x1e000
.data   
	Virtual Address: 0x7b000
	Virtual Size: 0x5944
	Raw Size: 0x2000
.rsrc   
	Virtual Address: 0x81000
	Virtual Size: 0x2ec0
	Raw Size: 0x3000
```

You can also dump the full content of a section by passing its index to *sections*

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

print pe.sections[0]
```

**Output**

```bash
[IMAGE_SECTION_HEADER]
0x1F8      0x0   Name:                          .text
0x200      0x8   Misc:                          0x5BF81   
0x200      0x8   Misc_PhysicalAddress:          0x5BF81   
0x200      0x8   Misc_VirtualSize:              0x5BF81   
0x204      0xC   VirtualAddress:                0x1000    
0x208      0x10  SizeOfRawData:                 0x5C000   
0x20C      0x14  PointerToRawData:              0x1000    
0x210      0x18  PointerToRelocations:          0x0       
0x214      0x1C  PointerToLinenumbers:          0x0       
0x218      0x20  NumberOfRelocations:           0x0       
0x21A      0x22  NumberOfLinenumbers:           0x0       
0x21C      0x24  Characteristics:               0x60000020
```

## Modifying the Structures

One of the most interesting functionality of *pefile* is editing executables. All values support assignment, so we can easily alter an executable. Let's rename the `.text` section as an example:

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

print("[*] Original Section name = %s" % pe.sections[0].Name.decode('utf-8'))
print("[*] Editing values...\n")

# Edit values
pe.sections[0].Name = ".axc".encode()

# Save the change in another executable
new_exe_path = r"C:\Users\User\Desktop\new_putty.exe"
pe.write(new_exe_path)

# Check the values
new_pe = pefile.PE(new_exe_path)
print("[*] New Section name = %s" % new_pe.sections[0].Name.decode('utf-8'))
```

**Output**

```bash
[*] Original Section name = .text   
[*] Editing values...

[*] New Section name = .axc
```

Easy, right ?

## Code Injection

Now, let's try to inject code into the executable. Here we will inject a shellcode at the entry point. It will corrupt the executable as we will overwrite the orginal code to execute the shellcode. To do this, we will use the `set_bytes_at_offset()` method. It overwrite the bytes at the given file offset with the given string, it takes 2 arguments:

* `Offset`, containing the offset where we want to write the data 
* `Data`, the data...

```python
import pefile

exe_path = "c:\putty.exe"
pe = pefile.PE(exe_path)

# msfvenom -p windows/messagebox -f py
# Payload size: 272 bytes
# Final size of py file: 1308 bytes
shellcode = bytes(b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9")
shellcode += b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
shellcode += b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
shellcode += b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
shellcode += b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
shellcode += b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
shellcode += b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
shellcode += b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
shellcode += b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
shellcode += b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
shellcode += b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
shellcode += b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
shellcode += b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
shellcode += b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
shellcode += b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
shellcode += b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68"
shellcode += b"\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c"
shellcode += b"\x24\x0a\x89\xe3\x68\x58\x20\x20\x20\x68\x4d\x53\x46"
shellcode += b"\x21\x68\x72\x6f\x6d\x20\x68\x6f\x2c\x20\x66\x68\x48"
shellcode += b"\x65\x6c\x6c\x31\xc9\x88\x4c\x24\x10\x89\xe1\x31\xd2"
shellcode += b"\x52\x53\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08"

ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print("[*] Writting %d bytes at offset %s" % (len(shellcode), hex(ep)))
pe.set_bytes_at_offset(ep, shellcode)

new_exe_path = r"C:\Users\User\Desktop\new_putty.exe"
pe.write(new_exe_path)
```

By executing the new executable, you should see a message box indicating that the injection was successful.

**Note:** To generate the shellcode I used [Metasploit](https://www.metasploit.com).
{: .notice--info}

## Conclusion

There are many other features you should try like [matching PEiD signatures](https://github.com/erocarrera/pefile/blob/wiki/PEiDSignatures.md), but you should play be able to play with it on your own now. A large amount of resources is available on the official repository if you want to go further with *pefile*. Enjoy !

## Resources

* [Official GitHub for pefile](https://github.com/erocarrera/pefile)
* [Portable Executable on Wikipedia](https://en.wikipedia.org/wiki/Portable_Executable)
* [PE Format Specifications](http://go.microsoft.com/fwlink/p/?linkid=84140)
* [Undocumented PECOFF - Blackhat US 2011](https://media.blackhat.com/bh-us-11/Vuksan/BH_US_11_VuksanPericin_PECOFF_WP.pdf)
* [PE Format by Corkami](https://code.google.com/archive/p/corkami/wikis/PE.wiki)
* [Malware Researcher’s Handbook (Demystifying PE File)](http://resources.infosecinstitute.com/2-malware-researchers-handbook-demystifying-pe-file/)
