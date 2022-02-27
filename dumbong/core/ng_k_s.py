import gc

from gevent import monkey;
from gevent.event import Event

from speedmvba.core.smvba_e_cp import speedmvba

monkey.patch_all(thread=False)

import hashlib
import multiprocessing
import pickle
from crypto.ecdsa.ecdsa import ecdsa_vrfy
from multiprocessing import Process, Queue
import copy
import logging
import os
import traceback, time
import gevent
import numpy as np
from collections import namedtuple, defaultdict
from enum import Enum
from gevent import Greenlet
from gevent.queue import Queue
from honeybadgerbft.exceptions import UnknownTagError
from dumbong.core.nwabc import nwatomicbroadcast


def set_consensus_log(id: int):
    logger = logging.getLogger("consensus-node-" + str(id))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "consensus-node-" + str(id) + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


class BroadcastTag(Enum):
    X_VABA = 'X-VABA'


def broadcast_receiver_loop(recv_func, recv_queues):
    while True:
        sender, (tag, j, msg) = recv_func(timeout=1000)
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues

        try:
            # print("receiver_loop:", sender, msg)
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            print("error", sender, (tag, j, msg))
            traceback.print_exc(e)


class Dumbo_NG_k_s:
    def __init__(self, sid, pid, S, B, N, f, sPK, sSK, sPK1, sSK1, sPK2s, sSK2, ePK, eSK, send, recv, K=3, mute=False,
                 debug=False):

        self.sid = sid
        self.id = pid
        self.SLOTS_NUM = S
        self.B = B
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
        self.K = K
        self.round = 0
        self.transaction_buffer = defaultdict(lambda: gevent.queue.Queue())
        self._per_round_recv = {}
        self.output_list = [multiprocessing.Queue() for _ in range(N * self.K)]
        self.fast_recv = [multiprocessing.Queue() for _ in range(N * self.K)]
        self.mvba_recv = multiprocessing.Queue()
        self.debug = debug
        self.s_time = 0
        self.e_time = 0
        self.tx_cnt = 0
        self.txcnt = 0
        self.txdelay = 0
        self.latency = 0
        self.mute = mute
        self.threads = []
        self.local_view = [0] * (N * self.K)
        self.local_view_s = [0] * (N * self.K)
        self.txs = defaultdict(lambda: defaultdict())
        self.sigs = defaultdict(lambda: defaultdict(lambda: tuple()))
        self.sts = defaultdict(lambda: defaultdict())
        self.r = 1
        self.hashtable = defaultdict((lambda: defaultdict()))
        self.st_sum = 0
        self.help_count = 0
        self.op = 0
        self.ap = 0
        self.countpoint = 0
        self.abc_count = 0
        self.vaba_thread = None

    def submit_tx(self, tx, k):
        """Appends the given transaction to the transaction buffer.

        :param tx: Transaction to append to the buffer.
        :param k: instance to append
        """
        self.transaction_buffer[k].put_nowait(tx)

    def buffer_size(self, k):
        """Return the size of the transaction buffer.

        :param k: instance to append
        """
        return self.transaction_buffer[k].qsize()

    def run_bft(self):
        """Run the Dumbo-NG protocol."""

        self.s_time = time.time()
        if self.mute:
            muted_nodes = [each * 3 + 1 for each in range(int((self.N - 1) / 3))]
            if self.id in muted_nodes:
                # T = 0.00001
                while True:
                    time.sleep(10)

        for i in range(self.N * self.K):
            self.sigs[i][0] = ()
            self.txs[i][0] = ""

        def _recv_loop():
            """Receive messages."""
            if os.getpid() == self.op:
                return
            if os.getpid() == self.ap:
                return
            # print("start recv loop...", os.getpid())

            while True:
                # gevent.sleep(0)
                try:
                    (sender, (r, msg)) = self._recv()
                    if msg[0] == 'PROPOSAL' or msg[0] == 'VOTE':
                        self.fast_recv[int(msg[1][6:])].put_nowait((sender, msg))
                    else:
                        self.mvba_recv.put((r, (sender, msg)))
                except:
                    continue

        def _get_output():
            """Get output from broadcast and run MVBA."""

            self._per_round_recv = {}  # Buffer of incoming messages
            self.op = os.getpid()

            def handelmsg():
                """Handel MVBA message for each round"""
                if os.getpid() != self.op:
                    return
                while True:
                    (r0, (sender, msg)) = self.mvba_recv.get(timeout=100)
                    if r0 < self.round:
                        continue
                    if r0 not in self._per_round_recv:
                        self._per_round_recv[r0] = gevent.queue.Queue()

                    self._per_round_recv[r0].put_nowait((sender, msg))

            self._recv_thread = Greenlet(handelmsg)
            self._recv_thread.start()
            del self.transaction_buffer[0]

            def _make_send(r):
                def _send(j, o):
                    self._send(j, (r, o))

                return _send

            wait_input_signal = Event()
            wait_input_signal.clear()
            vaba_input = None

            def get_list():
                """Get output from broadcast"""
                nonlocal vaba_input
                count = [0 for _ in range(self.N)]
                while True:
                    for i in range(self.N):
                        for j in range(self.K):
                            while self.output_list[i * self.K + j].qsize() > 0:
                                out = self.output_list[i * self.K + j].get()
                                (_, s, tx, sig, st) = out
                                if s > self.local_view[i * self.K + j]:
                                    self.local_view[i * self.K + j] = s
                                # always store the transactions and QCs of the latest 200 slot
                                # and delete the old stuff from memory
                                self.txs[i * self.K + j][s] = tx
                                self.sigs[i * self.K + j][s] = sig
                                self.sts[i * self.K + j][s] = st
                                if self.round > 200:    # delete the transactions
                                    del_p = max(0, self.local_view[i * self.K + j] - 200)
                                    try:
                                        for p in self.txs[i * self.K + j].keys() and p < del_p:
                                            del self.txs[i * self.K + j][p]
                                            del self.sigs[i * self.K + j][p]
                                            del self.sts[i * self.K + j][p]
                                    except:
                                        pass
                            if self.local_view[i * self.K + j] - self.local_view_s[
                                i * self.K + j] > 0 and wait_input_signal.isSet() == False:
                                count[i] = 1
                    if count.count(1) >= (self.N - self.f) and wait_input_signal.isSet() == False:
                        count = [0 for _ in range(self.N)]
                        lview = copy.copy(self.local_view)
                        vaba_input = (lview, [copy.copy(self.sigs[j][lview[j]]) for j in range(self.N * self.K)],
                                      [copy.copy(self.txs[j][lview[j]]) for j in range(self.N * self.K)])
                        wait_input_signal.set()
                    gevent.sleep(0)

            gevent.spawn(get_list)

            while True:
                start = time.time()

                if self.round not in self._per_round_recv:
                    self._per_round_recv[self.round] = gevent.queue.Queue()

                send_r = _make_send(self.round)
                recv_r = self._per_round_recv[self.round].get

                wait_input_signal.wait()
                self._run_VABA_round(self.round, vaba_input, send_r, recv_r)
                wait_input_signal.clear()

                if self.round > self.countpoint:
                    self.txcnt += self.tx_cnt

                end = time.time()
                if self.st_sum == 0 or ((self.tx_cnt / self.B) - self.help_count) == 0:
                    self.latency = (end - start) * 1.5 / (self.round - self.countpoint + 1)
                else:
                    self.latency = (((self.tx_cnt / self.B) - self.help_count) * end - self.st_sum) / (
                            (self.tx_cnt / self.B) - self.help_count)

                if self.round > self.countpoint:
                    self.txdelay += (end - start)

                if self.logger != None and self.round > self.countpoint:
                    self.logger.info(
                        "node: %d run: %f total delivered Txs: %d, average delay: %f, tps: %f" %
                        (self.id, end - self.s_time, self.txcnt,
                         self.latency, self.txcnt / self.txdelay))

                if self.round > 2:
                    del self._per_round_recv[self.round - 2]

                self.round += 1

        """start to run the protocol"""
        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))

        def _make_send_nwabc():
            """send nwabc message"""
            def _send(j, o):
                self._send(j, ('', o))

            return _send


        def abcs():
            """run n nwabc instances"""
            self.ap = os.getpid()
            for i in range(self.N):
                for j in range(self.K):
                    send = _make_send_nwabc()
                    recv = self.fast_recv[i * self.K + j].get
                    self._run_nwabc(send, recv, i, j)
            gevent.joinall(self.threads)

        self._abcs = Process(target=abcs)
        self._recv_output = Process(target=_get_output)

        self._abcs.start()
        self._recv_output.start()

        self._recv_thread = gevent.spawn(_recv_loop)

        self._abcs.join(timeout=86400)

        self.e_time = time.time()

    def _run_nwabc(self, send, recv, i, j):
        """Run one NWABC instance.

        :param int i: slot id
        :param int j: instance j
        :param send:
        :param recv:
        """
        if os.getpid() == self.op:
            return 0

        sid = self.sid
        pid = self.id
        N = self.N
        f = self.f

        epoch_id = sid + 'nw'

        leader = i
        t = gevent.spawn(nwatomicbroadcast, epoch_id + str(i * self.K + j), pid, N, f, self.B,
                         self.sPK2s, self.sSK2, leader,
                         self.transaction_buffer[j].get_nowait, self.output_list[i * self.K + j].put_nowait, recv, send,
                         self.logger, 1)
        self.threads.append(t)

    def _run_VABA_round(self, r, tx_to_send, send, recv):
        """Run one VABA round.
        :param int r: round id
        :param tx_to_send: Transaction(s) to process.
        :param send:
        :param recv:
        """

        # Unique sid for each round
        sid = self.sid + ':' + str(r)
        pid = self.id
        N = self.N
        f = self.f
        vaba_recv = gevent.queue.Queue()
        vaba_input = gevent.queue.Queue(1)
        vaba_output = gevent.queue.Queue(1)
        vaba_input.put_nowait(tx_to_send)
        bc_recv_loop_thread = gevent.spawn(broadcast_receiver_loop, recv, vaba_recv)
        self.tx_cnt = 0

        def _setup_vaba():
            """setup one MVBA instance"""

            def vaba_send(k, o):
                send(k, ('X_VABA', '', o))

            def vaba_predicate(vj):
                """check the external validity of MVBA"""
                siglist = [tuple() for _ in range(N * self.K)]
                (view, siglist, hashlist) = vj

                # check n-f gorws
                cnt2 = 0
                for i in range(N):
                    for j in range(self.K):
                        if view[i * self.K + j] == 0:
                            continue
                        if view[i * self.K + j] - self.local_view_s[i * self.K + j] > 0:
                            cnt2 += 1
                            break
                if cnt2 < N - f:
                    print("less than n-f")
                    return False

                # check all sig
                for i in range(N):
                    for j in range(self.K):
                        # find tx in local first
                        if view[i * self.K + j] <= self.local_view[i * self.K + j]:
                            try:
                                assert self.txs[i * self.K + j][view[i * self.K + j]] == hashlist[i * self.K + j]
                                return True
                            except Exception as e:
                                pass
                        # then find in hash table
                        if view[i * self.K + j] in self.hashtable[i * self.K + j].keys():
                            try:
                                assert self.hashtable[i * self.K + j][view[i * self.K + j]] == hashlist[i * self.K + j]
                            except:
                                return False
                        # have to check sig and regist in hash table
                        else:
                            sid_r = self.sid + 'nw' + str(i * self.K + j)
                            try:
                                digest2 = hashlist[i * self.K + j] + hash(str((sid_r, view[i * self.K + j])))
                                for item in siglist[i * self.K + j]:
                                    (sender, sig_p) = item
                                    assert ecdsa_vrfy(self.sPK2s[sender], digest2, sig_p)
                            except AssertionError:
                                if self.logger is not None: self.logger.info("ecdsa signature failed!")
                                print("ecdsa signature failed!")
                                return False
                            self.hashtable[i * self.K + j][view[i * self.K + j]] = hashlist[i * self.K + j]
                return True

            self.vaba_thread = gevent.spawn(speedmvba, sid + 'VABA' + str(r), pid, N, f,
                                            self.sPK, self.sSK, self.sPK2s, self.sSK2,
                                            vaba_input.get, vaba_output.put_nowait,
                                            vaba_recv.get, vaba_send, vaba_predicate, logger=self.logger)

        _setup_vaba()

        out = vaba_output.get()
        (view, s, txhash) = out
        self.help_count = 0
        self.st_sum = 0
        for i in range(N):
            for j in range(self.K):
                # check sigs in s[i][view[i]]
                if self.local_view[i * self.K + j] < view[i * self.K + j]:
                    # TODO: ADD PULLING BLOCK
                    for t in range(self.local_view[i * self.K + j] + 1, view[i * self.K + j] + 1):
                        tx = "catch"
                        self.txs[i * self.K + j][t] = tx
                for t in range(self.local_view_s[i * self.K + j] + 1, view[i * self.K + j]):
                    try:
                        add = self.sts[i * self.K + j][t]

                    except:
                        add = 0
                        self.help_count += 1
                    self.st_sum += add
                    self.tx_cnt += self.B
        # reset the view
        self.local_view_s = view
        bc_recv_loop_thread.kill()