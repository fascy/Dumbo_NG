from gevent import monkey;

import network

monkey.patch_all(thread=False)

import time
import random
import traceback
from typing import List, Callable
from gevent import Greenlet
from myexperiements.sockettest.dumbo_node import DumboBFTNode
from myexperiements.sockettest.sdumbo_node import SDumboBFTNode
from myexperiements.sockettest.ng_k_s_node import NGSNode
from network.socket_server import NetworkServer
from network.socket_client import NetworkClient
from network.socket_client_ng import NetworkClient
from multiprocessing import Value as mpValue, Queue as mpQueue
from ctypes import c_bool


def instantiate_bft_node(sid, i, B, N, f, K, S, T, bft_from_server: Callable, bft_to_client: Callable, ready: mpValue,
                         stop: mpValue, protocol="ng", mute=False, F=100, debug=False, omitfast=False, countpoint=0):
    bft = None
    if protocol == 'dumbo':
        bft = DumboBFTNode(sid, i, B, N, f, bft_from_server, bft_to_client, ready, stop, K, mute=mute, debug=debug)
    elif protocol == 'sdumbo':
        bft = SDumboBFTNode(sid, i, B, N, f, bft_from_server, bft_to_client,  ready, stop, K, mute=mute, debug=debug)
    elif protocol == 'ng':
        bft = NGSNode(sid, i, S, T, B, F, N, f, bft_from_server, bft_to_client, ready, stop, K, mute=mute,
                      countpoint=countpoint)
    else:
        print("Only support dumbo or sdumbo or ng or dl")
    return bft


if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--sid', metavar='sid', required=True,
                        help='identifier of node', type=str)
    parser.add_argument('--id', metavar='id', required=True,
                        help='identifier of node', type=int)
    parser.add_argument('--N', metavar='N', required=True,
                        help='number of parties', type=int)
    parser.add_argument('--f', metavar='f', required=True,
                        help='number of faulties', type=int)
    parser.add_argument('--B', metavar='B', required=True,
                        help='size of batch', type=int)
    parser.add_argument('--K', metavar='K', required=True,
                        help='rounds to execute', type=int)
    parser.add_argument('--S', metavar='S', required=False,
                        help='slots to execute', type=int, default=50)
    parser.add_argument('--T', metavar='T', required=False,
                        help='fast path timeout', type=float, default=1)
    parser.add_argument('--P', metavar='P', required=False,
                        help='protocol to execute', type=str, default="ng")
    parser.add_argument('--M', metavar='M', required=False,
                        help='whether to mute a third of nodes', type=bool, default=False)
    parser.add_argument('--F', metavar='F', required=False,
                        help='batch size of fallback path', type=int, default=100)
    parser.add_argument('--D', metavar='D', required=False,
                        help='whether to debug mode', type=bool, default=False)
    parser.add_argument('--O', metavar='O', required=False,
                        help='whether to omit the fast path', type=bool, default=False)
    parser.add_argument('--C', metavar='C', required=False,
                        help='point to start measure tps and latency', type=int, default=0)
    args = parser.parse_args()

    # Some parameters
    sid = args.sid
    i = args.id
    N = args.N
    f = args.f
    B = args.B
    K = args.K
    S = args.S
    T = args.T
    P = args.P
    M = args.M
    F = args.F
    D = args.D
    O = args.O
    C = args.C

    # Random generator
    rnd = random.Random(sid)

    # Nodes list
    addresses = [None] * N
    try:
        with open('hosts.config', 'r') as hosts:
            for line in hosts:
                params = line.split()
                pid = int(params[0])
                priv_ip = params[1]
                pub_ip = params[2]
                port = int(params[3])
                # print(pid, ip, port)
                if pid not in range(N):
                    continue
                if pid == i:
                    my_address = (priv_ip, port)
                addresses[pid] = (pub_ip, port)
        assert all([node is not None for node in addresses])
        print("hosts.config is correctly read")


        client_bft_mpq = mpQueue()
        #client_from_bft = client_bft_mpq.get
        client_from_bft = lambda: client_bft_mpq.get(timeout=0.00001)

        bft_to_client = client_bft_mpq.put_nowait

        server_bft_mpq = mpQueue()
        #bft_from_server = server_bft_mpq.get
        bft_from_server = lambda: server_bft_mpq.get(timeout=0.00001)
        server_to_bft = server_bft_mpq.put_nowait

        client_ready = mpValue(c_bool, False)
        server_ready = mpValue(c_bool, False)
        net_ready = mpValue(c_bool, False)
        stop = mpValue(c_bool, False)
        if P == 'ng':
            net_client = network.socket_client_ng.NetworkClient(my_address[1], my_address[0], i, addresses, client_from_bft, client_ready, stop)
        else:
            net_client = network.socket_client.NetworkClient(my_address[1], my_address[0], i, addresses, client_from_bft, client_ready, stop)
        net_server = NetworkServer(my_address[1], my_address[0], i, addresses, server_to_bft, server_ready, stop)
        bft = instantiate_bft_node(sid, i, B, N, f, K, S, T, bft_from_server, bft_to_client, net_ready, stop, P, M, F, D, O, C)

        net_server.start()
        net_client.start()

        while not client_ready.value and not server_ready.value:
            time.sleep(1)
            print("waiting for network ready...")

        with net_ready.get_lock():
            net_ready.value = True

        bft_thread = Greenlet(bft.run)
        bft_thread.start()
        bft_thread.join()

        with stop.get_lock():
            stop.value = True

        net_client.terminate()
        net_client.join()
        time.sleep(1)
        net_server.terminate()
        net_server.join()

    except FileNotFoundError or AssertionError as e:
        traceback.print_exc()
