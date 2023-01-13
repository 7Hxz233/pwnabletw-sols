import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 31337))
sock.listen(1)

while True:
    print("[+] waiting for connection...")
    clifd, addr = sock.accept()
    print("[+] Connected from :", addr)

    while True:
        msg = clifd.recv(4096)
        print(len(msg))
        print(msg)
        break