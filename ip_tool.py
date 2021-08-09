nodes = '''
i-0aeb7d4aefcbc39d2	3.239.74.105	172.31.71.134
i-04ba7fff0c080e359	18.221.111.52	172.31.34.251
i-064ede6d88a97b2c1	54.153.84.72	172.31.13.93
i-0e593c7e606a2736e	34.219.43.16	172.31.5.65
i-0359804d967c697a0	13.235.54.20	172.31.24.197
i-03d308cdb5a29075e	3.36.101.124	172.31.57.165
i-045ee55e64c3ab9a4	54.255.193.26	172.31.47.149
i-0440ff53802bf0e28	3.25.239.29	172.31.6.250
i-0bb6ff9a448742d0d	18.183.198.173	172.31.2.176
i-00d60534d688bb7e2	15.223.28.222	172.31.37.63
'''

num_regions = 16
N = 10

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
