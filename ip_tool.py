nodes = '''
i-0aeb7d4aefcbc39d2	3.236.4.183	172.31.71.134
i-04ba7fff0c080e359	3.129.10.123	172.31.34.251
i-064ede6d88a97b2c1	13.52.75.188	172.31.13.93
i-0e593c7e606a2736e	18.237.185.233	172.31.5.65
i-0359804d967c697a0	3.109.0.159	172.31.24.197
i-0dccc597f2796ee6a	15.165.48.103	172.31.53.200
i-045ee55e64c3ab9a4	13.229.91.168	172.31.47.149
i-0d10d180116a44b97	3.25.167.43	172.31.33.61
i-085337530f5ad0c4c	35.75.3.235	172.31.30.62
i-00d60534d688bb7e2	15.223.43.245	172.31.37.63
i-01ab8e519fd7082aa	18.196.183.133	172.31.8.165
i-02b668962a8f9a669	54.78.154.212	172.31.26.166
i-0e9bfacd66dcc7b1e	18.133.73.138	172.31.1.221
i-0e64e39ba66bb10de	13.37.57.134	172.31.33.172
i-018ace45f74c4c0da	13.48.129.212	172.31.11.77
i-020d8cf0d00c69d5c	15.228.76.75	172.31.22.61

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
