# x64-calc-popper-shellcode — NASM Shellcode Demo

A position-independent x64 Windows shellcode implementation demonstrating 
PEB walking, custom hash-based API resolution, and XOR string obfuscation.
Written in NASM as a learning exercise to understand what happens below 
the C abstraction layer.

## What it does

Resolves `WinExec` from `kernel32.dll` at runtime without using the Windows 
Import Address Table, then executes a XOR-encoded command string.

## Techniques demonstrated

**PEB Walking**  
Traverses the Process Environment Block's `InMemoryOrderModuleList` to locate 
loaded modules without calling `LoadLibrary` or `GetProcAddress`. Handles the 
`LDR_DATA_TABLE_ENTRY` offset arithmetic manually to recover module base addresses.

**Custom Hash-based API Resolution**  
Instead of storing plaintext API names, a custom salted hash function identifies 
target functions by comparing computed hashes against stored constants. Supports 
both ASCII and wide string inputs for handling module names (wide) and export 
names (ASCII).

Hash algorithm: `hash = char + (SALT ^ SALT_2 ^ i) + (hash << 6) + (hash << 16) - hash`  
Final XOR step applied to the result for additional obfuscation.

**XOR String Obfuscation**  
Target command string is stored XOR-encoded in the `.text` section and decoded 
at runtime onto the stack, avoiding plaintext strings in the binary.

**PE Export Directory Parsing**  
Manually walks the PE export directory structures (`AddressOfNames`, 
`AddressOfFunctions`, `AddressOfNameOrdinals`) to resolve function addresses 
from the export table RVAs.

## Build

```nasm
nasm -f win64 calc_peb.nasm -o calc_peb.obj
gcc calc_peb.obj -o calc_peb.exe -nostartfiles
```

## Notes

- Written as a learning exercise — payload target is calc.exe
- Hash constants and XOR key are visible in source by design for educational clarity
