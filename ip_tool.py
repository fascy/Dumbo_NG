nodes = '''
i-04b0c58ec012d305d	54.204.94.178	172.31.16.133
i-056076d984d436f84	3.136.26.242	172.31.12.189
i-0bda848bc69c8cea6	54.183.238.26	172.31.18.20
i-0970458591f398966	35.84.208.252	172.31.55.91
i-0ba9bf23815374cce	3.110.89.29	172.31.21.99
i-0b2dc028b90a0e61c	3.37.29.144	172.31.17.57
i-03983d1b44cae8616	13.212.183.86	172.31.13.224
i-02007bebe931a89e6	3.105.228.106	172.31.1.171
i-0f0d77dfba9a3fd3e	54.199.255.252	172.31.40.69
i-054869f3694c1e827	3.99.46.113	172.31.38.194
i-0048bf8ce5573fbf5	18.157.74.81	172.31.1.0
i-0a922336d9fa5f623	34.254.233.245	172.31.19.99
i-07868c7652de78d72	13.40.113.80	172.31.0.187
i-0401999e704202816	15.188.50.57	172.31.34.192
i-053e25ff3880b37c5	13.48.46.10	172.31.33.113
i-0a29e2d16f00632d1	54.233.199.89	172.31.34.45

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

print("N=%d" % len(public_ips))

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
