import gevent
from gevent import monkey;

from myexperiements.sockettest.dl_sockets_node import DLNode
from myexperiements.sockettest.nwabcs_k_node import NwAbcskNode
from myexperiements.sockettest.x_d_node import XDNode
from myexperiements.sockettest.x_k_node import XDKNode
from myexperiements.sockettest.x_k_s_node import XDSNode
from network.sockets_client import NetworkClients
from network.sockets_server import NetworkServers

monkey.patch_all(thread=False)

import time
import random
import traceback
from typing import List, Callable
from gevent import Greenlet

from network.socket_server import NetworkServer
from network.socket_client import NetworkClient
from multiprocessing import Value as mpValue, Queue as mpQueue
from ctypes import c_bool


def instantiate_bft_node(sid, i, B, N, f, K, S, T, bft_from_server1: Callable, bft_to_client1: Callable,bft_from_server2: Callable, bft_to_client2: Callable, ready: mpValue,
                         stop: mpValue, protocol="mule", mute=False, F=100, debug=False, omitfast=False):
    bft = None
    if protocol == 'dl':
        bft = DLNode(sid, i, S, T, B, F, N, f, bft_from_server1, bft_to_client1, bft_from_server2, bft_to_client2, ready, stop, K, mute=mute)

    else:
        print("Only support dl")
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
                        help='protocol to execute', type=str, default="mule")
    parser.add_argument('--M', metavar='M', required=False,
                        help='whether to mute a third of nodes', type=bool, default=False)
    parser.add_argument('--F', metavar='F', required=False,
                        help='batch size of fallback path', type=int, default=100)
    parser.add_argument('--D', metavar='D', required=False,
                        help='whether to debug mode', type=bool, default=False)
    parser.add_argument('--O', metavar='O', required=False,
                        help='whether to omit the fast path', type=bool, default=False)
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

    # Random generator
    rnd = random.Random(sid)

    # Nodes list
    addresses1 = [None] * N
    addresses2 = [None] * N
    try:
        with open('hosts1_config', 'r') as hosts:
            for line in hosts:
                params = line.split()
                pid = int(params[0])
                priv_ip = params[1]
                pub_ip = params[2]
                port1 = int(params[3])
                port2 = int(params[4])
                print(pid, priv_ip, port1, port2)
                if pid not in range(N):
                    continue
                if pid == i:
                    my_address1 = (priv_ip, port1)
                    my_address2 = (priv_ip, port2)
                addresses1[pid] = (pub_ip, port1)
                addresses2[pid] = (pub_ip, port2)
        assert all([node is not None for node in addresses1])
        assert all([node is not None for node in addresses2])
        print("hosts.config is correctly read")

        # bft_from_server, server_to_bft = mpPipe(duplex=True)
        # client_from_bft, bft_to_client = mpPipe(duplex=True)

        client_bft_mpq1 = mpQueue()
        client_from_bft1 = lambda: client_bft_mpq1.get(timeout=0.00001)

        client_bft_mpq2 = mpQueue()
        client_from_bft2 = lambda: client_bft_mpq2.get(timeout=0.00001)

        bft_to_client1 = client_bft_mpq1.put_nowait
        bft_to_client2 = client_bft_mpq2.put_nowait

        server_bft_mpq1 = mpQueue()
        #bft_from_server = server_bft_mpq.get
        bft_from_server1 = lambda: server_bft_mpq1.get(timeout=0.00001)
        server_to_bft1 = server_bft_mpq1.put_nowait

        server_bft_mpq2 = mpQueue()
        #bft_from_server = server_bft_mpq.get
        bft_from_server2 = lambda: server_bft_mpq2.get(timeout=0.00001)
        server_to_bft2 = server_bft_mpq2.put_nowait

        client_ready1 = mpValue(c_bool, False)
        server_ready1 = mpValue(c_bool, False)
        client_ready2 = mpValue(c_bool, False)
        server_ready2 = mpValue(c_bool, False)
        net_ready = mpValue(c_bool, False)
        stop = mpValue(c_bool, False)

        net_server1 = NetworkServers(my_address1[1], my_address2[1], my_address1[0], my_address2[0], i, addresses1, addresses2,
                                    server_to_bft1, server_to_bft2, server_ready1, server_ready2, stop, stop, 1, 2)
        net_client1 = NetworkClients(my_address1[1], my_address2[1], my_address1[0], my_address2[0], i, addresses1, addresses2,
                                     client_from_bft1, client_from_bft2, client_ready1, client_ready2, stop, stop, 0, 1)
        # net_server2 = NetworkServer(my_address2[1], my_address2[0], i, addresses2, server_to_bft2, server_ready2, stop, 2)
        # net_client2 = NetworkClient(my_address2[1], my_address2[0], i, addresses2, client_from_bft2, client_ready2, stop, 0)
        bft = instantiate_bft_node(sid, i, B, N, f, K, S, T, bft_from_server1, bft_to_client1,
                                   bft_from_server2, bft_to_client2, net_ready, stop, P, M, F, D, O)

        net_server1.start()
        net_client1.start()

        while not client_ready1.value and not server_ready1.value \
                and not client_ready2.value and not server_ready2.value:
            time.sleep(1)
            print("waiting for network ready...")

        with net_ready.get_lock():
            net_ready.value = True

        bft_thread = Greenlet(bft.run)
        bft_thread.start()
        bft_thread.join()

        with stop.get_lock():
            stop.value = True

        net_client1.terminate()
        net_client1.join()

        time.sleep(1)

        net_server1.terminate()
        net_server1.join()


    except FileNotFoundError or AssertionError as e:
        traceback.print_exc()
