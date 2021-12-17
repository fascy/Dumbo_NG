nodes = '''
i-02ededd400c69c5fb	67.202.53.102	172.31.24.131
i-095e08e0ddfa8e48d	3.19.61.130	172.31.43.53
i-09f2187242facc8ae	54.193.162.133	172.31.29.206
i-0380c471e74119c62	44.242.168.180	172.31.53.111
i-024dfdc24479066f1	3.110.170.95	172.31.36.191
i-05014e6b38047cc1b	3.35.165.139	172.31.60.40
i-0b6625beb9a43ba63	13.214.187.96	172.31.10.218
i-0637721c1f3f4e1f1	54.252.159.28	172.31.1.213
i-0e10b48d07b52c54a	52.194.193.187	172.31.47.33
i-0ac48b6625d91dd9c	3.98.37.39	172.31.42.136
i-0319b276aee029a0d	3.68.221.255	172.31.1.59
i-0369e004358b92f50	3.249.189.122	172.31.20.254
i-0b7b763416587693a	3.10.176.104	172.31.6.193
i-0f46c6e4348f25b6a	13.38.118.9	172.31.33.69
i-0c32e74d2f9532fed	16.170.244.178	172.31.47.106
i-02a4172d8f50d4ff0	15.228.58.45	172.31.39.15


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
