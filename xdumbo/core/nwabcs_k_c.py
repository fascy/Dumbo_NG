from collections import deque, defaultdict

from gevent import monkey;

monkey.patch_all(thread=False)

import hashlib
import logging
import os
import pickle
import gevent
import time
import numpy as np
from gevent import Greenlet
from gevent.queue import Queue
from xdumbo.core.nwabc import nwatomicbroadcast
from crypto.threshsig.boldyreva import TBLSPrivateKey, TBLSPublicKey
from crypto.ecdsa.ecdsa import PrivateKey


def set_consensus_log(id: int):
    logger = logging.getLogger("consensus-node-" + str(id))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "consensus-node-" + str(id) + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
    logger.addHandler(file_handler)
    return logger


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


class Nwabcsk():
    """n nwabc objects used to run the protocol

    :param str sid: The base name of the common coin that will be used to
        derive a nonce to uniquely identify the coin.
    :param int pid: Node id.
    :param int Bfast: Batch size of transactions.
    :param int Bacs: Batch size of transactions.
    :param int N: Number of nodes in the network.
    :param int f: Number of faulty nodes that can be tolerated.
    :param TBLSPublicKey sPK: Public key of the (f, N) threshold signature.
    :param TBLSPrivateKey sSK: Signing key of the (f, N) threshold signature.
    :param TBLSPublicKey sPK1: Public key of the (N-f, N) threshold signature.
    :param TBLSPrivateKey sSK1: Signing key of the (N-f, N) threshold signature.
    :param list sPK2s: Public key(s) of ECDSA signature for all N parties.
    :param PrivateKey sSK2: Signing key of ECDSA signature.
    :param str ePK: Public key of the threshold encryption.
    :param str eSK: Signing key of the threshold encryption.
    :param send:
    :param recv:
    :param K: a test parameter to specify break out after K epochs
    """

    def __init__(self, sid, pid, S, Bfast, N, f, sPK, sSK, sPK1, sSK1, sPK2s, sSK2, ePK, eSK, send, recv, K=3,
                 mute=False):

        self.SLOTS_NUM = S
        self.FAST_BATCH_SIZE = Bfast
        self.sid = sid
        self.id = pid
        self.N = N
        self.f = f
        self.sPK = sPK
        self.sSK = sSK
        self.sPK1 = sPK1
        self.sSK1 = sSK1
        self.sPK2s = sPK2s
        self.sSK2 = sSK2
        self.ePK = ePK
        self.eSK = eSK
        self._send = send
        self._recv = recv
        self.logger = set_consensus_log(pid)
        self.transaction_buffer = defaultdict(lambda: Queue())
        self.output_list = defaultdict(lambda: Queue())
        self.fast_recv = defaultdict(lambda: Queue())

        self.K = K

        self.s_time = 0
        self.e_time = 0

        self.txcnt = 0
        self.txdelay = 0

        self.mute = mute
        self.threads = []

    def submit_tx(self, tx, j):
        """Appends the given transaction to the transaction buffer.

        :param tx: Transaction to append to the buffer.
        """
        self.transaction_buffer[j].put_nowait(tx)

    def run_bft(self):
        """Run the Mule protocol."""

        if self.mute:
            muted_nodes = [each * 3 + 1 for each in range(int((self.N - 1) / 3))]
            if self.id in muted_nodes:
                # T = 0.00001
                while True:
                    time.sleep(10)

        def _recv_loop():
            """Receive messages."""
            while True:
                # gevent.sleep(0)
                try:
                    (sender, msg) = self._recv()
                    self.fast_recv[msg[1]].put_nowait((sender, msg))
                except:
                    continue

        self._recv_thread = Greenlet(_recv_loop)
        self._recv_thread.start()

        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))

        # For each sid
        nwabc_threads = []
        for i in range(0, self.N):
            for j in range(self.K):
                send = self._send
                recv = self.fast_recv['sidA' + 'nw' + str(i)+str(j)].get

                self._run(send, recv, i, j)

        gevent.joinall(self.threads, timeout=45)

        self.e_time = time.time()
        self.txcnt = 0
        for i in range(self.N * self.K):
            self.txcnt += self.output_list[i].qsize() * self.FAST_BATCH_SIZE
        if self.logger != None:
            self.logger.info("node %d breaks in %f seconds with total delivered Txs %d and tps %f" %
                             (self.id, self.e_time - self.s_time, self.txcnt, self.txcnt / (self.e_time - self.s_time)))

        print("node %d breaks in %f seconds with total delivered Txs %d and tps %f" %
              (self.id, self.e_time - self.s_time, self.txcnt, self.txcnt / (self.e_time - self.s_time))
              )

    #

    def _run(self, send, recv, i, j):
        """Run one protocol epoch.

        :param int i : pid
        :param int j : jth instance of node i
        :param send:
        :param recv:
        """

        sid = self.sid
        pid = self.id
        N = self.N
        f = self.f
        k = self.K

        epoch_id = sid + 'nw'
        # hash_genesis = hash(epoch_id)

        leader = i
        t = gevent.spawn(nwatomicbroadcast, epoch_id + str(i)+str(j), pid, N, f, self.FAST_BATCH_SIZE,
                        self.sPK2s, self.sSK2, leader,
                        self.transaction_buffer[j].get_nowait, self.output_list[i*k+j].put_nowait, recv, send, self.logger)
        self.threads.append(t)
        # nwabc_threads.join()



