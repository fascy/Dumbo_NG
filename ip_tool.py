nodes = '''
i-02ededd400c69c5fb	54.198.185.56	172.31.24.131
i-095e08e0ddfa8e48d	18.191.148.76	172.31.43.53
i-09f2187242facc8ae	54.219.66.62	172.31.29.206
i-0380c471e74119c62	44.234.85.72	172.31.53.111
i-024dfdc24479066f1	35.154.147.251	172.31.36.191
i-05014e6b38047cc1b	3.35.197.33	172.31.60.40
i-0b6625beb9a43ba63	13.214.175.135	172.31.10.218
i-0637721c1f3f4e1f1	54.153.131.176	172.31.1.213
i-0e10b48d07b52c54a	52.195.11.210	172.31.47.33
i-0ac48b6625d91dd9c	3.97.209.79	172.31.42.136
i-0319b276aee029a0d	3.126.255.173	172.31.1.59
i-0369e004358b92f50	63.33.51.229	172.31.20.254
i-0b7b763416587693a	35.177.133.186	172.31.6.193
i-0f46c6e4348f25b6a	35.180.156.9	172.31.33.69
i-0c32e74d2f9532fed	13.53.132.48	172.31.47.106
i-02a4172d8f50d4ff0	54.233.133.239	172.31.39.15




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
