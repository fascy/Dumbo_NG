from gevent import monkey;

from dispersedledger.core.PCBC import provablecbc
from honeybadgerbft.core.reliablebroadcast import merkleVerify, decode
from speedmvba.core.smvba_e import speedmvba

monkey.patch_all(thread=False)

import hashlib
import multiprocessing
import pickle
from crypto.ecdsa.ecdsa import ecdsa_vrfy
from multiprocessing import Process, Queue

import json
import logging
import os
import traceback, time
import gevent
import numpy as np
from collections import namedtuple, defaultdict
from enum import Enum
from gevent import Greenlet
from gevent.queue import Queue
from honeybadgerbft.core.honeybadger_block import honeybadger_block
from honeybadgerbft.exceptions import UnknownTagError
from xdumbo.core.nwabc import nwatomicbroadcast


# v : k nwabc instances
# using smvba

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



class RECOVER(Process):

    def __init__(self, sid, pid, B, N, f, sPK, sSK, sPK1, sSK1, sPK2s, sSK2, recv, K=3, mute=False, debug=False, logger=None):

        super().__init__()
        self.sid = sid
        self.id = pid
        self.B = B
        self.N = N
        self.f = f
        self.sPK = sPK
        self.sSK = sSK
        self.sPK1 = sPK1
        self.sSK1 = sSK1
        self.sPK2s = sPK2s
        self.sSK2 = sSK2
        self._recv = recv
        self.logger = logger
        self.K = K

        self.bc_instances = defaultdict(lambda: defaultdict())
        self.share_bc = multiprocessing.Queue()

        self.re_instances = defaultdict(lambda: defaultdict(lambda: [None for i in range(self.N)]))
        self.re_count = defaultdict(lambda: defaultdict(int))
        self.output_list = [multiprocessing.Queue() for _ in range(N)]
        self.tobe_retrieval = multiprocessing.Queue()
        self.bmp = 0
        self.rp = 0
        self.bc_mv_recv = multiprocessing.Queue()
        self.retrieval_recv = multiprocessing.Queue()

        self.debug = debug

        # self.s_time = 0
        self.s_time = multiprocessing.Value('d', 0.0)
        self.e_time = 0
        self.tx_cnt = 0
        self.txcnt = 0
        self.txdelay = 0
        self.l_c = 0
        self.mute = mute
        self.threads = []
        self.r = 1

    def run(self):
        """Run the DL protocol."""
        # print("==============", self.id)
        if self.mute:
            muted_nodes = [each * 3 + 1 for each in range(int((self.N - 1) / 3))]
            if self.id in muted_nodes:
                # T = 0.00001
                while True:
                    time.sleep(10)
        if self.id ==0: print("main:", os.getpid())

        def _recv_loop_r():
            """Receive messages."""
            st = 0
            # print("start recv loop...", os.getpid())
            # self._send(1, (1, "test msg"))
            while True:
                try:
                    gevent.sleep(0)
                    (sender, (r, msg)) = self._recv()
                    # if self.id == 3: print("************recover recv2:", sender, msg[0], msg[1][0])
                    if msg[0] == 'RETURN':
                        self.retrieval_recv.put((sender, msg))
                except:
                    continue
                # self._recv_thread.start()

        def _run_retrieval():
            self.rp = os.getpid()
            """
            v: 0 has sent
            v: -1 wait to sent
            """
            if self.id == 0: print("recover:", self.rp)
            return_recvs = [Queue() for _ in range(self.N)]

            def _recv_msg():
                if os.getpid() != self.rp:
                    return

                while True:
                    sender, msg = self.retrieval_recv.get(timeout=1000)
                    _, (sid, send_list) = msg
                    for i in range(len(send_list)):
                        # print(send_list[i])
                        (sid, leader, v, rst) = send_list[i]
                        return_recvs[leader].put_nowait((sender, (sid, v, rst)))
                    # if self.id == 1: print("get a new msg ", sid, leader, "at ", time.time())

            _re_thread = gevent.spawn(_recv_msg)

            def _recover(j):
                # deal with recover of leader j
                if os.getpid() != self.rp:
                    return

                while True:
                    sender, msg = return_recvs[j].get()
                    # print(sender, msg[0])
                    # print("recover recv: ", sender, msg[0])
                    (sid, (chunk, branch, root), rst) = msg

                    if not self.re_instances[sid][j]:
                        # has recovered
                        continue
                    try:
                        assert merkleVerify(self.N, chunk, root, branch, sender)
                    except Exception as e:
                        print("Failed to validate VAL message:", sender)
                        continue
                    self.re_instances[sid][j][sender] = chunk
                    self.re_count[sid][j] += 1
                    # print(sid, leader, "instance append", chunk)
                    if self.re_count[sid][j] == self.N - (2 * self.f):
                        # m = decode(self.N - (2 * self.f), self.N, self.re_instances[sid][j])
                        st = rst

                        et = time.time()
                        # if self.id == 1: print("get end time of", sid, j, "at", time.time())
                        self.re_instances[sid][j].clear()
                        if self.logger != None:
                            tx_cnt = self.B
                            self.txcnt += tx_cnt
                            self.l_c += (et - st)
                            self.txdelay = et - self.s_time
                            block_count = self.txcnt / self.B
                            # print("block count", block_count)
                            self.logger.info(
                                'Node %d Delivers Block of %s with %d TXs, %d in total, tps:%f, %f, %f'
                                % (self.id, str(sid) + str(j), tx_cnt, self.txcnt,
                                   self.txcnt / self.txdelay, self.l_c / block_count, et))
                            # if self.id == 3: print(
                            #     'Node %d Delivers ACS Block of %s with having %d TXs, %d in total,latency:%f, tps:%f, %f, %f'
                            #     % (self.id, str(sid) + str(j), tx_cnt, self.txcnt, et - st,
                            #        self.txcnt / self.txdelay, self.l_c / block_count, et))
                            # if self.id ==3 : print("remain", self.retrieval_recv.qsize())

            # _collect_thread = gevent.spawn(_collect)
            _recover_threads = [None] * self.N
            for i in range(self.N):
                _recover_threads[i] = gevent.spawn(_recover, i)
            gevent.joinall(_recover_threads)


        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))

        self._recv_thread = gevent.spawn(_recv_loop_r)
        self._recover = gevent.spawn(_run_retrieval)
        self._recover.join()
        self._recv_thread.join()
        # self._bc_mvba.join()
        # print("-----------------------------start to join")
        # self._recv_output.join()
        self.e_time = time.time()

