# -*- coding: utf-8 -*-
from pwn import *
import sys 
context.terminal = ["tmux","splitw","-h"]
# sh = ssh(host='pwnable.kr',user='passcode',port=2222,password='guest')
lib = "/lib/x86_64-linux-gnu/libc.so.6"
sys.argv[0] = exe = './test'
elf = ELF(exe)
libc = ELF(lib)
host = '127.0.0.1'
port = 10003
if args.I:
    context.log_level='debug'
def local():
    return process(sys.argv)
def remote():
    return connect(host, port)
def one_gadget():
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f', '-l', '2',lib]),encoding = "utf-8").split(' ')
    return (list(map(int,one_ggs)))
def get_IO_str_jumps():
    IO_file_jumps_offset = libc.sym['_IO_file_jumps']
    IO_str_underflow_offset = libc.sym['_IO_str_underflow']
    for ref_offset in libc.search(p64(IO_str_underflow_offset)):
        possible_IO_str_jumps_offset = ref_offset - 0x20
        if possible_IO_str_jumps_offset > IO_file_jumps_offset:
            return possible_IO_str_jumps_offset
            
start = remote if args.R else local

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
l32  = lambda     : u32(io.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
l64  = lambda     : u64(io.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
#==================================================
io = start()


io.interactive()
