nodes = '''
i-0aeb7d4aefcbc39d2	3.236.18.83	172.31.71.134
i-04ba7fff0c080e359	3.137.138.147	172.31.34.251
i-064ede6d88a97b2c1	18.144.154.186	172.31.13.93
i-0e593c7e606a2736e	18.237.215.154	172.31.5.65
i-0359804d967c697a0	3.108.222.113	172.31.24.197
i-0dccc597f2796ee6a	3.37.17.16	172.31.53.200
i-045ee55e64c3ab9a4	13.250.16.63	172.31.47.149
i-0d10d180116a44b97	13.210.140.157	172.31.33.61
i-085337530f5ad0c4c	35.74.70.67	172.31.30.62
i-00d60534d688bb7e2	15.223.45.138	172.31.37.63
i-01ab8e519fd7082aa	3.66.211.177	172.31.8.165
i-02b668962a8f9a669	52.209.130.227	172.31.26.166
i-0e9bfacd66dcc7b1e	18.134.9.2	172.31.1.221
i-0e64e39ba66bb10de	35.180.227.1	172.31.33.172
i-018ace45f74c4c0da	13.49.138.55	172.31.11.77
i-020d8cf0d00c69d5c	18.230.64.86	172.31.22.61


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
