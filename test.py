import socket

local_ip = socket.gethostbyname(socket.gethostname())
print(local_ip)

test_ip = '77.88.55.242'
print(socket.gethostbyname(test_ip))
print(socket.gethostbyaddr(test_ip))