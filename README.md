# CRC32_Search_And_NOP

I wrote this tool to help in the search of CRC32 opcodes. These are a sort of low
level protections which are often added into debugging to act as an error-detecting
function that uses a CRC32 algorithm to detect changes between source and target data.
They will usually follow such patterns F2 ?? 0F 38 F1 ?? .


This tool is supposed to make this easier to find these opcodes. In it's current
state, it will look at mapped memory and search for the pattern above. You can
choose to nop these if you choose to do so.

examples on how to run the program:

```
.\Crc32Scanner.exe --file "c:\path\to\your\program.exe"  --printmm --locate --nop
```

Arguments:
```
--file   : specifies the file you will load.
--printmm: will print out the Memmapped blocks
--locate : will search for the address of these blocks
--ignore : will ignore blocks seperated by comma.
--nop    :tells to nop each crc32 found.
keepsuspended: will keep the process suspended after noping. 
```


Additional examples:
 ```
"--file=/path/to/my/file.exe --locate --nop --ignore 0x000007ff4567845ff,0x000007ff4567845ff # will launch the file, NOP all CRC32 Addresses skipping the search in those blocks\n"
"--file=/path/to/my/file.exe --printmm # prints memory blocks \n"
"--file=/path/to/my/file.exe --nop -k #search all blocks and NOP all Crc32s Found , but leave process suspended\n"
```
