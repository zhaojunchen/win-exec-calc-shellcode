; 参数压栈！
BITS 32
SECTION .text

%include 'type-conversion.asm'
xor edx, edx
; 分配字符串空间
push B2DW('t','i','p',0)
push esp
pop eax
push 0x00000000

push B2DW('0', '1', '8', '4')
push B2DW('0', '1', '5', '0')
push B2DW('0', '1', '7', '3')
push B2DW('G', '1', ':', '2')
push esp
pop ecx; &(学号)
; 填充MessageBoxA参数
push edx;
push eax;
push ecx
push edx
    ; stack = NULL & (学号)NULL NULL

    xor ecx, ecx
    mov eax, [fs:ecx + 0x30]; EAX = PEB [FS:EDX + 0x30]
    mov eax, [eax + 0xc]; EAX = PEB->Ldr
    mov esi, [eax + 0x14]; ESI = PEB->Ldr.InMemOrder
    lodsd; EAX = Second module
    xchg eax, esi; EAX = ESI, ESI = EAX
    lodsd; EAX = Third(kernel32)
    mov ebx, [eax + 0x10]; EBX = Base address
    mov edx, [ebx + 0x3c]; EDX = DOS->e_lfanew
    add edx, ebx; EDX = PE Header
    mov edx, [edx + 0x78]; EDX = Offset export table
    add edx, ebx; EDX = Export table
    mov esi, [edx + 0x20]; ESI = Offset namestable
    add esi, ebx; ESI = Names table
    xor ecx, ecx; EXC = 0

    Get_Function:
inc ecx; Increment the ordinal
    lodsd; Get name offset
    add eax, ebx; Get function name
    cmp dword [eax], 0x50746547; GetP
    jnz Get_Function
    cmp dword [eax + 0x4], 0x41636f72; rocA
    jnz Get_Function
    cmp dword [eax + 0x8], 0x65726464; ddre
    jnz Get_Function
    mov esi, [edx + 0x24]; ESI = Offset ordinals
    add esi, ebx; ESI = Ordinals table
    mov cx, [esi + ecx * 2]; Number of function
    dec ecx
    mov esi, [edx + 0x1c]; Offset address table
    add esi, ebx; ESI = Address table
    mov edx, [esi + ecx * 4]; EDX = Pointer(offset)
    add edx, ebx; EDX = GetProcAddress
    push edx; GetProcessAddress

    ; 寻找load函数
    ; edx getPeocess
    ; ebx kernel32
    xor ecx, ecx
    push ecx; 0x00
    push B2DW('a', 'r', 'y', 'A')
    push B2DW('L', 'i', 'b', 'r')
    push B2DW('L', 'o', 'a', 'd')
    push esp; &LoadLibraryA
    push ebx; kernel32 address

    call edx; GetProcAddress
    ; eax load
    add esp, 0x10; pop "LoadLibrary"
    ; ecx = 0
    ; 加载msvcrt

    push B2DW('l', 'l', 0x00, 0x00)
    push B2DW('3', '2', '.', 'd')
    push B2DW('u', 's', 'e', 'r')
    push esp; "user32.dll"
    call eax; LoadLibrary("msvcrt.dll")
    add esp, 0xc
    ; eax = msvcrt.dll
    ; esi = dll
    pop edx;
    xor ecx, ecx
    ; MessageBoxA
    push B2DW('o', 'x', 'A', 0x00)
    push B2DW('a', 'g', 'e', 'B')
    push B2DW('M', 'e', 's', 's')

    push esp; &"MessageBoxA"
    push eax; user32.dll address
    
    call edx; GetProc("MessageBoxA")
    add esp, 0xc
    call eax
    add esp, 0x18
; MASM
; // Project8_shellcode.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
; //

; #include <iostream>
; #include <windows.h>
; using namespace std;
; typedef bool(__stdcall *Fun)(int a, int b);
; int main()
; {
; 	/*FARPROC(_stdcall *pgo1)(HMODULE,LPCSTR) = GetProcAddress;
; 	cout << *pgo1<<"   "<<pgo1<<endl;*/
; 	__asm{
; 		; 参数压栈！
; #define B2W(b1, b2)                      (((b2) << 8) + (b1))
; #define W2DW(w1, w2)                     (((w2) << 16) + (w1))
; #define DW2QW(dw1, dw2)                  (((dw2) << 32) + (dw1))
; #define B2DW(b1, b2, b3, b4)               ((B2W(b3, b4) << 16) + B2W(b1, b2))
; #define B2QW(b1, b2, b3, b4, b5, b6, b7, b8)   ((B2DW(b5, b6, b7, b8) << 32) + B2DW(b1, b2, b3, b4))
; #define W2QW(w1, w2, w3, w4)               ((W2DW(w3, w4) << 32) + W2DW(w1, w2))

; 		xor edx, edx
; 		; 分配字符串空间
; 		push B2DW('t','i','p',0)
; 		push esp
; 		pop eax
; 		push 0x00000000
		
; 		push B2DW('0', '1', '8', '4')
; 		push B2DW('0', '1', '5', '0')
; 		push B2DW('0', '1', '7', '3')
; 		push B2DW('G', '1', ':', '2')
; 		push esp
; 		pop ecx; &(学号)
; 		; 填充MessageBoxA参数
; 		push edx;
; 		push eax;
; 		push ecx
; 		push edx
; 			; stack = NULL & (学号)NULL NULL

; 			xor ecx, ecx
; 			mov eax, fs:[ecx + 0x30]; EAX = PEB
; 			mov eax, [eax + 0xc]; EAX = PEB->Ldr
; 			mov esi, [eax + 0x14]; ESI = PEB->Ldr.InMemOrder
; 			lodsd; EAX = Second module
; 			xchg eax, esi; EAX = ESI, ESI = EAX
; 			lodsd; EAX = Third(kernel32)
; 			mov ebx, [eax + 0x10]; EBX = Base address
; 			mov edx, [ebx + 0x3c]; EDX = DOS->e_lfanew
; 			add edx, ebx; EDX = PE Header
; 			mov edx, [edx + 0x78]; EDX = Offset export table
; 			add edx, ebx; EDX = Export table
; 			mov esi, [edx + 0x20]; ESI = Offset namestable
; 			add esi, ebx; ESI = Names table
; 			xor ecx, ecx; EXC = 0

; 			Get_Function:
; 		inc ecx; Increment the ordinal
; 			lodsd; Get name offset
; 			add eax, ebx; Get function name
; 			cmp dword ptr[eax], 0x50746547; GetP
; 			jnz Get_Function
; 			cmp dword ptr[eax + 0x4], 0x41636f72; rocA
; 			jnz Get_Function
; 			cmp dword ptr[eax + 0x8], 0x65726464; ddre
; 			jnz Get_Function
; 			mov esi, [edx + 0x24]; ESI = Offset ordinals
; 			add esi, ebx; ESI = Ordinals table
; 			mov cx, [esi + ecx * 2]; Number of function
; 			dec ecx
; 			mov esi, [edx + 0x1c]; Offset address table
; 			add esi, ebx; ESI = Address table
; 			mov edx, [esi + ecx * 4]; EDX = Pointer(offset)
; 			add edx, ebx; EDX = GetProcAddress
; 			push edx; GetProcessAddress

; 			; 寻找load函数
; 			; edx getPeocess
; 			; ebx kernel32
; 			xor ecx, ecx
; 			push ecx; 0x00
; 			push B2DW('a', 'r', 'y', 'A')
; 			push B2DW('L', 'i', 'b', 'r')
; 			push B2DW('L', 'o', 'a', 'd')
; 			push esp; &LoadLibraryA
; 			push ebx; kernel32 address

; 			call edx; GetProcAddress
; 			; eax load
; 			add esp, 0x10; pop "LoadLibrary"
; 			; ecx = 0
; 			; 加载msvcrt

; 			push B2DW('l', 'l', 0x00, 0x00)
; 			push B2DW('3', '2', '.', 'd')
; 			push B2DW('u', 's', 'e', 'r')
; 			push esp; "user32.dll"
; 			call eax; LoadLibrary("msvcrt.dll")
; 			add esp, 0xc
; 			; eax = msvcrt.dll
; 			; esi = dll
; 			pop edx;
; 			xor ecx, ecx
; 			; MessageBoxA
; 			push B2DW('o', 'x', 'A', 0x00)
; 			push B2DW('a', 'g', 'e', 'B')
; 			push B2DW('M', 'e', 's', 's')

; 			push esp; &"MessageBoxA"
; 			push eax; user32.dll address
			
; 			call edx; GetProc("MessageBoxA")
; 			add esp, 0xc
; 			call eax
; 			add esp, 0x18
; 	}
; 	return 0;
   
; }