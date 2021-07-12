from gevent import monkey;

monkey.patch_all(thread=False)

import hashlib
import multiprocessing
import pickle
from crypto.ecdsa.ecdsa import ecdsa_vrfy
from dumbobft.core.validatedagreement import validatedagreement
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


class BroadcastTag(Enum):
    X_VABA = 'X-VABA'


# BroadcastReceiverQueues = namedtuple(
#    'BroadcastReceiverQueues', 'X-VABA')


def broadcast_receiver_loop(recv_func, recv_queues):
    while True:
        sender, (tag, j, msg) = recv_func(timeout=1000)
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues

        # if tag == BroadcastTag.X_NWABC.value:
        #    recv_queue = recv_queue[j]
        try:
            # print("receiver_loop:", sender, msg)
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            print("error", sender, (tag, j, msg))
            traceback.print_exc(e)


class XDumbo_d:
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
        self.round = 0  # Current block number
        self.transaction_buffer = gevent.queue.Queue()
        self._per_round_recv = [multiprocessing.Queue() for _ in range(200)]
        # self.output_list = defaultdict(lambda: Queue())
        self.output_list = [multiprocessing.Queue() for _ in range(N)]
        self.fast_recv = [multiprocessing.Queue() for _ in range(N)]
        # self.mvba_recv = multiprocessing.Queue()
        self.K = K
        self.debug = debug

        self.s_time = 0
        self.e_time = 0
        self.tx_cnt = 0
        self.txcnt = 0
        self.txdelay = 0

        self.mute = mute
        self.threads = []

        self.local_view = [0] * N
        self.local_view_s = [0] * N
        self.txs = defaultdict(lambda: defaultdict())
        self.sigs = defaultdict(lambda: defaultdict(lambda: tuple()))
        self.r = 1
        self.hashtable = defaultdict((lambda: defaultdict()))

        self.op = 0
        self.ap = 0

    def submit_tx(self, tx):
        """Appends the given transaction to the transaction buffer.

        :param tx: Transaction to append to the buffer.
        """
        self.transaction_buffer.put_nowait(tx)

    def run_bft(self):
        """Run the XDumbo protocol."""

        if self.mute:
            muted_nodes = [each * 3 + 1 for each in range(int((self.N - 1) / 3))]
            if self.id in muted_nodes:
                # T = 0.00001
                while True:
                    time.sleep(10)

        for i in range(self.N):
            self.sigs[i][0] = ()
            self.txs[i][0] = ""

        def _recv_loop():
            """Receive messages."""
            if os.getpid() == self.op:
                return
            if os.getpid() == self.ap:
                return
            print("start recv loop...", os.getpid())

            while True:
                # gevent.sleep(0)
                try:
                    (sender, (r, msg)) = self._recv()

                    # self.logger.info('recv1' + str((sender, o)))
                    if msg[0] == 'PROPOSAL' or msg[0] == 'VOTE':
                        self.fast_recv[int(msg[1][6:])].put_nowait((sender, msg))
                        # print(self.id, 'recv' + str((sender, msg[0],int(msg[1][6:]))))
                    else:
                        # (tag, j, m) = msg
                        # Maintain an *unbounded* recv queue for each epoch
                        # Buffer this message
                        # print(self.id, 'recv' + str((sender, msg[0])))
                        self._per_round_recv[r].put_nowait((sender, msg))
                        # self.mvba_recv.put((sender, (r, msg)))
                        # print("mvba put:", self._per_round_recv[r])
                except:
                    continue

        self._recv_thread = Process(target=_recv_loop)
        self._recv_thread.start()

        # self._recv_thread.start()

        def _get_output():
            self.op = os.getpid()
            print("output process id:", self.op)

            count = [0 for _ in range(self.N)]
            while True:
                r = self.round
                # print(r, "start!")
                start = time.time()
                for i in range(self.N):
                    # print("output list:", self.output_list[i])
                    while self.output_list[i].qsize() > 0:
                        out = self.output_list[i].get()
                        # print("nwabc out:", out)
                        (_, s, tx, sig) = out
                        self.local_view[i] += 1
                        self.txs[i][self.local_view[i]] = tx
                        self.sigs[i][self.local_view[i]] = sig

                        # print("------------output:", out)
                    if self.local_view[i] - self.local_view_s[i] > 0:
                        count[i] = 1
                # print("round ", r, ":", count)
                if count.count(1) >= self.N - self.f:
                    print(self.id, self.local_view)
                    vaba_input = (self.local_view, [self.sigs[j][self.local_view[j]] for j in range(self.N)],
                                  [hash(self.txs[j][self.local_view[j]]) for j in range(self.N)])

                    def _make_send(r):
                        def _send(j, o):
                            self._send(j, (r, o))

                        return _send

                    send_r = _make_send(r)
                    recv_r = self._per_round_recv[r].get
                    vaba_output = self._run_VABA_round(r, vaba_input, send_r, recv_r)
                    if self.logger != None:
                        self.tx_cnt = str(vaba_output).count("Dummy")
                        if self.round > 2:
                            self.txcnt += self.tx_cnt
                        self.logger.info(
                            'Node %d Delivers ACS Block in Round %d with having %d TXs, %d TXs in total' % (
                                self.id, r, self.tx_cnt, self.txcnt))
                    end = time.time()
                    if self.round > 2:
                        self.txdelay += (end - start)
                    if self.logger != None:
                        self.logger.info('ACS Block Delay at Node %d: ' % self.id + str(end - start))

                    if self.logger != None and self.round > 2:
                        self.logger.info(
                            "node %d has run %f seconds with total delivered Txs %d, average delay %f, tps: %f" %
                            (self.id, end - self.s_time, self.txcnt, self.txdelay / self.round,
                             self.txcnt / self.txdelay))
                    if self.round > 2:
                        print("node %d has run %f seconds with total delivered Txs %d, average delay %f, tps: %f" %
                          (self.id, end - self.s_time, self.txcnt, self.txdelay / self.round,
                           self.txcnt / self.txdelay))
                    self.round += 1
                    count = [0 for _ in range(self.N)]
                    # print(self.round)
                else:
                    # gevent.sleep(0)
                    # print("not enough tx still")
                    continue

        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))

        def _make_send_nwabc():
            def _send(j, o):
                self._send(j, ('', o))

            return _send

        # run n nwabc instances
        def abcs():
            self.ap = os.getpid()
            print("run n abcs:", os.getpid())
            for i in range(0, self.N):
                send = _make_send_nwabc()
                recv = self.fast_recv[i].get

                self._run_nwabc(send, recv, i)
            gevent.joinall(self.threads)

            # return 0

        # self._recv_thread = gevent.spawn(_recv_loop)
        # abcs()
        self._abcs = Process(target=abcs)

        self._recv_output = Process(target=_get_output)

        self._abcs.start()

        self._recv_output.start()
        # self._recv_output = gevent.spawn(_get_output)
        # self._abcs = gevent.spawn(abcs)
        self._abcs.join()
        # print("-----------------------------start to join")
        # self._recv_output.join()
        self.e_time = time.time()

        if self.logger != None:
            self.logger.info("node %d breaks in %f seconds with total delivered Txs %d, average delay %f, tps: %f" %
                             (self.id, self.e_time - self.s_time, self.txcnt, self.txdelay / (self.round + 1),
                              self.txcnt / (self.e_time - self.s_time)))

        print("node %d breaks in %f seconds with total delivered Txs %d, average delay %f, tps: %f" %
              (self.id, self.e_time - self.s_time, self.txcnt, self.txdelay / (self.round + 1),
               self.txcnt / (self.e_time - self.s_time)))

        while True:
            pass

    def _run_nwabc(self, send, recv, i):
        """Run one NWABC instance.

        :param int e: epoch id
        :param send:
        :param recv:
        """
        # print("run_nwabc is called! ", os.getpid())
        if os.getpid() == self.op:
            return 0
        sid = self.sid
        pid = self.id
        N = self.N
        f = self.f

        epoch_id = sid + 'nw'
        # hash_genesis = hash(epoch_id)

        leader = i
        # print(self.transaction_buffer.qsize())
        t = gevent.spawn(nwatomicbroadcast, epoch_id + str(i), pid, N, f, self.B,
                         self.sPK2s, self.sSK2, leader,
                         self.transaction_buffer.get_nowait, self.output_list[i].put_nowait, recv, send,
                         self.logger, os.getpid())
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
        # recv_queues = BroadcastReceiverQueues(X-VABA=vaba_recv)
        bc_recv_loop_thread = gevent.spawn(broadcast_receiver_loop, recv, vaba_recv)
        # bc_recv_loop_thread.start()
        # print(pid, "start vaba round", r)
        self.tx_cnt = 0

        def _setup_vaba():
            def vaba_send(k, o):
                """Threshold encryption broadcast."""
                """Threshold encryption broadcast."""
                send(k, ('X_VABA', '', o))

            def vaba_predicate(vj):
                siglist = [tuple() for _ in range(N)]
                (view, siglist, hashlist) = vj
                # check n-f gorws
                cnt2 = 0
                for i in range(N):
                    if view[i] == 0:
                        continue
                    if view[i] - self.local_view_s[i] > 0:
                        cnt2 += 1
                if cnt2 < N - f:
                    return False
                # check all sig
                for i in range(N):
                    # find tx in local first
                    if view[i] <= self.local_view[i]:
                        try:
                            assert hash(self.txs[i][view[i]]) == hashlist[i]
                        except:
                            return False
                    # then find in hash table
                    elif view[i] in self.hashtable[i].keys():
                        try:
                            assert self.hashtable[i][view[i]] == hashlist[i]
                        except:
                            return False
                    # have to check sig and regist in hash table
                    else:
                        sid_r = self.sid + 'nw' + str(i)
                        try:
                            digest2 = hashlist[i] + hash(str((sid_r, view[i])))
                            for item in siglist[i]:
                                # print(Sigma_p)
                                (sender, sig_p) = item
                                assert ecdsa_vrfy(self.sPK2s[sender], digest2, sig_p)
                        except AssertionError:
                            if self.logger is not None: self.logger.info("ecdsa signature failed!")
                            return False
                        self.hashtable[i][view[i]] = hashlist[i]
                return True

            if self.debug:
                vaba_thread = Greenlet(validatedagreement, sid + 'VABA' + str(r), pid, N, f,
                                       self.sPK, self.sSK, self.sPK1, self.sSK1, self.sPK2s, self.sSK2,
                                       vaba_input.get, vaba_output.put_nowait,
                                       vaba_recv.get, vaba_send, vaba_predicate, self.logger)
            else:
                vaba_thread = Greenlet(validatedagreement, sid + 'VABA' + str(r), pid, N, f,
                                       self.sPK, self.sSK, self.sPK1, self.sSK1, self.sPK2s, self.sSK2,
                                       vaba_input.get, vaba_output.put_nowait,
                                       vaba_recv.get, vaba_send, vaba_predicate, )

            vaba_thread.start()

        _setup_vaba()
        out = ""
        try:
            # print("vaba is waiting for output in round ", r)
            # gevent.sleep(0)
            out = vaba_output.get()
            # print(pid, "vaba out in round ", r, out[0])
        except:
            pass
        s = [tuple() for _ in range(N)]
        view = []
        (view, s, txhash) = out
        # print("view:", view, "  v_s", self.local_view_s, "v:", self.local_view)
        block = []
        for i in range(N):
            # check sigs in s[i][view[i]]
            if self.local_view[i] < view[i]:
                # TODO: ADD PULLING BLOCK
                for t in range(self.local_view[i] + 1, view[i] + 1):
                    tx = ""
                    for d in range(self.B):
                        tx += "Dummy TX..."
                    self.txs[i][t] = tx
                    self.sigs[i][t] = "some sigs..."
                    # print(self.txs[i][t])
            for t in range(self.local_view_s[i] + 1, view[i] + 1):
                # print("append tx", i, t, self.txs[i][t])
                block.append((self.txs[i][t], self.sigs[i][t]))
                # self.tx_cnt += 1
        self.local_view_s = view
        # print(block)
        return block
