from pwn import *

io = process("./DarkHeap")


gdb.attach(io)






io.interactive()
