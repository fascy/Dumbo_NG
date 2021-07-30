nodes = '''
i-0aeb7d4aefcbc39d2	3.236.7.40	172.31.71.134
i-04ba7fff0c080e359	18.118.45.253	172.31.34.251
i-064ede6d88a97b2c1	13.57.222.194	172.31.13.93
i-0e593c7e606a2736e	34.222.81.209	172.31.5.65
i-0359804d967c697a0	3.109.0.144	172.31.24.197
i-0ae4266290510cb68	3.35.241.194	172.31.57.235
i-045ee55e64c3ab9a4	13.212.37.233	172.31.47.149
i-0440ff53802bf0e28	52.63.254.19	172.31.6.250
i-0bb6ff9a448742d0d	54.95.14.185	172.31.2.176
i-00d60534d688bb7e2	3.99.12.44	172.31.37.63
i-01ab8e519fd7082aa	18.185.11.213	172.31.8.165
i-0481d31c5d4730e46	34.241.178.121	172.31.7.198
i-0e9bfacd66dcc7b1e	18.132.63.183	172.31.1.221
i-086d65edcb22efa03	15.237.110.8	172.31.8.166
i-018ace45f74c4c0da	16.170.37.130	172.31.11.77
i-020d8cf0d00c69d5c	15.228.51.206	172.31.22.61


'''

num_regions = 16
N = 16

n = int(N / num_regions)
r = N - num_regions * n

each_region_n = []
for i in range(num_regions):
    if r > 0:
        each_region_n.append(n + 1)
        r -= 1
    else:
        each_region_n.append(n)
print(each_region_n)

public_ips = []
private_ips = []

for line in nodes.splitlines():
    try:
        _, public, private = line.split()
        public_ips.append(public)
        private_ips.append(private)
    except:
        pass

print(len(public_ips))

print("# public IPs")
print("pubIPsVar=(", end='')
for i in range(len(public_ips) - 1):
    print("[%d]=\'%s\'" % (i, public_ips[i]))
i = len(public_ips) - 1
print("[%d]=\'%s\')" % (i, public_ips[i]))

print("# private IPs")
print("priIPsVar=(", end='')
for i in range(len(private_ips) - 1):
    print("[%d]=\'%s\'" % (i, private_ips[i]))
i = len(private_ips) - 1
print("[%d]=\'%s\')" % (i, private_ips[i]))
