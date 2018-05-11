import socket


socket.setdefaulttimeout(5)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('47.52.171.108',22))
a = sock.recv(512)
print a
sock.close()