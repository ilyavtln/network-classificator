import socket

local_ip = socket.gethostbyname(socket.gethostname())
print(local_ip)

test_ip = '224.0.0.251'
print(socket.gethostbyname(test_ip))
print(socket.gethostbyaddr(test_ip))