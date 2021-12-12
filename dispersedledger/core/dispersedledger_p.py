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


class BroadcastTag(Enum):
    ACS_PCBC = 'ACS_PCBC'
    ACS_VACS = 'ACS_VACS'


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('ACS_PCBC', 'ACS_VACS'))


def broadcast_receiver_loop(recv_func, recv_queues):
    while True:
        # gevent.sleep(0)
        sender, (tag, j, msg) = recv_func()
        # print(sender, "->", j, tag)
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]

        if tag == BroadcastTag.ACS_PCBC.value:
            recv_queue = recv_queue[j]
        try:
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            print("error", sender, (tag, j, msg))
            traceback.print_exc(e)


class DL:
    def __init__(self, sid, pid, B, N, f, sPK, sSK, sPK1, sSK1, sPK2s, sSK2, send1, recv1, send2, recv2, K=3, mute=False,
                 debug=False):

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
        self._send1 = send1
        self._recv1 = recv1
        self._send2 = send1
        self._recv2 = recv2
        self.logger = set_consensus_log(pid)
        self.K = K
        self.round = 0  # Current block number
        self.transaction_buffer = gevent.queue.Queue()
        self._per_round_recv = multiprocessing.Queue()
        self.bc_instances = defaultdict(lambda: defaultdict())
        self.share_bc = multiprocessing.Queue()

        # self.bc_instances = multiprocessing.Manager().dict(multiprocessing.Manager().dict())
        self.re_instances = defaultdict(lambda: defaultdict(lambda: [None for i in range(self.N)]))
        self.re_count = defaultdict(lambda: defaultdict(int))
        self.output_list = [multiprocessing.Queue() for _ in range(N)]
        self.tobe_retrieval = multiprocessing.Queue()
        self.bmp = 0
        self.rp = 0
        self.bc_mv_recv = multiprocessing.Queue()
        self.retrieval_recv = multiprocessing.Queue()

        self.debug = debug

        self.s_time = 0
        self.e_time = 0
        self.tx_cnt = 0
        self.txcnt = 0
        self.txdelay = 0

        self.mute = mute
        self.threads = []

        self.r = 1

    def submit_tx(self, tx):
        """Appends the given transaction to the transaction buffer.

        :param tx: Transaction to append to the buffer.
        """
        self.transaction_buffer.put_nowait(tx)

    def run_bft(self):
        """Run the DL protocol."""

        if self.mute:
            muted_nodes = [each * 3 + 1 for each in range(int((self.N - 1) / 3))]
            if self.id in muted_nodes:
                # T = 0.00001
                while True:
                    time.sleep(10)

        def _recv_loop_bm():
            """Receive messages."""
            if os.getpid() == self.bmp:
                return
            if os.getpid() == self.rp:
                return
            print("start recv loop...", os.getpid())
            # self._send(1, (1, "test msg"))
            while True:
                # gevent.sleep(0)
                try:

                    (sender, (r, msg)) = self._recv1()
                    # print("recv:", sender, r, msg)
                    # self.logger.info('recv1' + str((sender, o)))
                    # if msg[0] == 'RETRIEVAL' or msg[0] == 'RETURN':
                        # print(self.id, 'recv' + str((sender, msg[0])))
                    #    self.retrieval_recv.put((sender, msg))

                    self.bc_mv_recv.put((r, (sender, msg)))
                        # print("mvba put:", self._per_round_recv[r])def
                except:
                    continue
        def _recv_loop_r():
            """Receive messages."""
            if os.getpid() == self.bmp:
                return
            if os.getpid() == self.rp:
                return
            st = 0
            print("start recv loop...", os.getpid())
            # self._send(1, (1, "test msg"))
            while True:
                # gevent.sleep(0)
                try:

                    (sender, (r, msg)) = self._recv2()
                    # print("recv:", sender, r, msg)
                    # self.logger.info('recv1' + str((sender, o)))
                    if msg[0] == 'RETRIEVAL' or msg[0] == 'RETURN':
                        # print(self.id, 'recv' + str((sender, msg[0])))
                        self.retrieval_recv.put((sender, msg))
                except:
                    continue

        # self._recv_thread.start()
        def _run_retrieval():
            self.rp = os.getpid()

            def ask_broadcast(o):
                self._send2(-1, ('', ('RETRIEVAL', o)))

            def return_send(o):
                self._send2(-1, ('', ('RETURN', o)))

            def _store():
                while True:
                    try:
                        (sid, leader, value, st) = self.share_bc.get_nowait()

                        # if self.id == 1: print("get", sid, leader, "at", time.time())
                        try:
                            #has recover not store or send
                            (g, v, s) = self.bc_instances[sid][leader]
                            if g == 2 and v == 0:
                                self.bc_instances[sid][leader] = (2, value, st)
                            if g == 3:
                                if v == 0:
                                    return_send((sid, leader, value))
                                    self.bc_instances[sid][leader] = (3, 0, st)
                        except:
                            self.bc_instances[sid][leader] = (1, value, st)
                    except:
                        gevent.sleep(0.0001)
                        continue

            def _ask():
                if os.getpid() != self.rp:
                    return
                while True:
                    try:
                        (sid, leader, root) = self.tobe_retrieval.get_nowait()
                        # if self.id == 1: print("get tobe recover:", sid, leader, root)
                        try:
                            (g, v, st) = self.bc_instances[sid][leader]
                            if g == 1 and v != 0:
                                return_send((sid, leader, v))
                                self.bc_instances[sid][leader] = (g, 0, st)
                        except:
                            self.bc_instances[sid][leader] = 2, 0, 0
                            pass
                    except:
                        gevent.sleep(0)
                        continue

            ask_recv = Queue()
            return_recvs = [Queue() for _ in range(self.N)]

            def _recv_msg():
                if os.getpid() != self.rp:
                    return

                while True:
                    gevent.sleep(0)
                    sender, msg = self.retrieval_recv.get(timeout=1000)
                    (_, (sid, leader, v)) = msg
                    return_recvs[leader].put_nowait((sender, (sid, v)))
                    # if self.id == 1: print("get a new msg ", sid, leader, "at ", time.time())

            _re_thread = gevent.spawn(_recv_msg)
            """
            def _collect():
                if os.getpid() != self.rp:
                    return

                while True:
                    gevent.sleep(0)
                    sender, msg = ask_recv.get()
                    (_, (sid, leader, root)) = msg
                    # print(sid, leader)
                    try:
                        g, value, t = self.bc_instances[sid][leader]
                        if value[0] == 0:
                            print(self.id, "did not store this value")
                            continue
                        if value[2] != root:
                            print("wrong root to retrieval, get ", root, "while stored ", value[2])
                            continue
                        return_send(sender, (sid, leader, value))
                        # self._send(sender, ('', ('RETURN', sid, leader, value)))
                        # if self.id == 1: print("send return", sid, leader)
                    except KeyError:
                        print(self.id, "did not store this", sid, leader, root)
            """
            def _recover(j):
                #deal with recover of leader j
                if os.getpid() != self.rp:
                    return

                while True:
                    # gevent.sleep(0)
                    sender, msg = return_recvs[j].get()

                    # print(sender, msg[0])
                    # print("recover recv: ", sender, msg[0])
                    (sid, (chunk, branch, root)) = msg
                    # if self.id == 1: print("get a new msg ", sid, j, "at ", time.time())
                    # print(self.id, "recv return ", sid, leader, chunk)
                    try:
                        g, value, t = self.bc_instances[sid][j]
                    except:
                        g = -1
                    if not self.re_instances[sid][j]:
                        # has recovered
                        continue
                    #if g > 0 and root != value[2]:
                    #    print("return wrong root to retrieval, get ", root, "while stored ", value[2])
                    try:
                        assert merkleVerify(self.N, chunk, root, branch, sender)
                    except Exception as e:
                        print("Failed to validate VAL message:", e)
                        continue
                    self.re_instances[sid][j][sender] = chunk
                    self.re_count[sid][j] += 1
                    # print(sid, leader, "instance append", chunk)
                    if self.re_count[sid][j] == self.N - (2 * self.f):
                        # if self.id == 1: print("get f+1 msg and start to decode", sid, j, "at", time.time())

                        m = decode(self.N - (2 * self.f), self.N, self.re_instances[sid][j])
                        # if self.id == 1: print("finish decode", sid, j, "at", time.time())
                        try:
                            g, v, st = self.bc_instances[sid][j]
                            self.bc_instances[sid][j] = 3, v, st
                        except:
                            self.bc_instances[sid][j] = 3, 0, 0
                        et = time.time()
                        # if self.id == 1: print("get end time of", sid, j, "at", time.time())
                        self.re_instances[sid][j].clear()
                        if self.logger != None:
                            tx_cnt = str(m).count("Dummy")
                            self.txcnt += tx_cnt
                            self.txdelay = et - self.s_time
                            self.logger.info(
                                'Node %d Delivers ACS Block of %s with having %d TXs, %d in total,latency:%f, tps:%f, %f'
                                % (self.id, str(sid) + str(j), tx_cnt, self.txcnt, et - st,
                                   self.txcnt / self.txdelay, et))
                            print(
                                'Node %d Delivers ACS Block of %s with having %d TXs, %d in total,latency:%f, tps:%f, %f'
                                % (self.id, str(sid) + str(j), tx_cnt, self.txcnt, et - st,
                                   self.txcnt / self.txdelay, et))
                            print("remain", self.retrieval_recv.qsize())
            _store_thread = gevent.spawn(_store)
            _ask_thread = gevent.spawn(_ask)
            # _collect_thread = gevent.spawn(_collect)
            for i in range(self.N):
                _recover_thread = gevent.spawn(_recover, i)
            while True:
                gevent.sleep(0)
                pass

        def _run_bc_mvba():
            self._per_round_recv = {}  # Buffer of incoming messages
            self.bmp = os.getpid()
            print("run_bc_mvba process id:", self.bmp)

            def handelmsg():
                if os.getpid() != self.bmp:
                    return
                while True:
                    (r0, (sender, msg)) = self.bc_mv_recv.get(timeout=100)
                    if r0 not in self._per_round_recv:
                        self._per_round_recv[r0] = gevent.queue.Queue()

                    self._per_round_recv[r0].put_nowait((sender, msg))

            self._recv_thread = Greenlet(handelmsg)
            self._recv_thread.start()

            while True:
                # print(r, "start!")
                start = time.time()

                if self.round not in self._per_round_recv:
                    self._per_round_recv[self.round] = gevent.queue.Queue()

                tx_to_send = []
                for _ in range(self.B):
                    tx_to_send.append(self.transaction_buffer.get_nowait())

                # print(self.id, "append tx:", tx_to_send)

                def _make_send(r):
                    def _send(j, o):
                        self._send1(j, (r, o))

                    return _send

                send_r = _make_send(self.round)
                recv_r = self._per_round_recv[self.round].get

                new_tx = self._run_BC_MVBA_round(self.round, tx_to_send, send_r, recv_r)
                # self._run_VABA_round(self.round, vaba_input, send_r, recv_r)

                if self.logger != None:
                    self.logger.info(
                        'Node %d Delivers ACS in Round %d' % (self.id, self.round))

                # if self.id == 3: print('Node %d Delivers ACS in Round %d' % (self.id, self.round))
                end = time.time()

                if self.logger != None:
                    self.logger.info('ACS Delay at Node %d: ' % self.id + str(end - start))
                    # print('ACS Delay at Node %d: ' % self.id + str(end - start))

                self.round += 1
                if self.round >= self.K:
                    break

        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))

        self._bc_mvba = Process(target=_run_bc_mvba)
        self._retrieval = Process(target=_run_retrieval)

        self._bc_mvba.start()
        self._retrieval.start()
        self._recv_thread1 = gevent.spawn(_recv_loop_bm)
        self._recv_thread2 = gevent.spawn(_recv_loop_r)
        self._recv_thread1.join()
        self._recv_thread2.join()
        self._retrieval.join()
        # self._bc_mvba.join()
        # print("-----------------------------start to join")
        # self._recv_output.join()
        self.e_time = time.time()

    def _run_BC_MVBA_round(self, r, tx_to_send, send, recv):
        """Run one PCBC and MVBA round.
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

        pcbc_recvs = [gevent.queue.Queue() for _ in range(N)]
        vacs_recv = gevent.queue.Queue()
        my_pcbc_input = gevent.queue.Queue(1)

        vacs_input = gevent.queue.Queue(1)
        vacs_output = gevent.queue.Queue(1)

        recv_queues = BroadcastReceiverQueues(
            ACS_PCBC=pcbc_recvs,
            ACS_VACS=vacs_recv
        )

        bc_recv_loop_thread = gevent.spawn(broadcast_receiver_loop, recv, recv_queues)

        # send(2, (2, "msg2"))
        def _setup_pcbc(j):
            """Setup the sub protocols RBC, BA and common coin.
                        :param int j: Node index for which the setup is being done.
                        """

            def pcbc_send(k, o):
                """"
                :param k: Node to send.
                :param o: Value to send.
                """
                send(k, ('ACS_PCBC', j, o))
                # print(k, 'ACS_PCBC', o[0])

            # Only leader gets input
            if pid == j:
                # print(j, json.dumps(tx_to_send))
                my_pcbc_input.put(json.dumps(tx_to_send))
                pcbc_input = my_pcbc_input.get
            else:
                pcbc_input = None

            if self.debug:
                pcbc_thread = gevent.spawn(provablecbc, sid + 'PCBC' + str(r) + str(j), pid, N, f,
                                           self.sPK2s, self.sSK2, j,
                                           pcbc_input, pcbc_recvs[j].get, pcbc_send, self.logger)
            else:
                pcbc_thread = gevent.spawn(provablecbc, sid + 'PCBC' + str(r) + str(j), pid, N, f,
                                           self.sPK2s, self.sSK2, j,
                                           pcbc_input, pcbc_recvs[j].get, pcbc_send, self.logger)

            def wait_for_prbc_output():
                value, sigs = pcbc_thread.get()
                (chunk, branch, root) = value
                st = time.time()
                self.bc_instances[sid + 'PCBC' + str(r)][j] = 1, root, sigs
                self.share_bc.put((sid + 'PCBC' + str(r), j, value, st))
                # if self.id == 1: print("put", sid + 'PCBC' + str(r), j, "at", time.time())
                # print(self.id, "output in ", sid + 'PCBC' + str(r)+str(j))
                # pcbc_outputs[j].put_nowait((value, proof))

            gevent.spawn(wait_for_prbc_output)

        values = [None] * N

        def _setup_vacs():
            def vacs_send(k, o):
                """Threshold encryption broadcast."""
                """Threshold encryption broadcast."""
                send(k, ('ACS_VACS', '', o))

            while len(self.bc_instances[sid + 'PCBC' + str(r)]) < N - f:
                gevent.sleep(0)
            # print("N - f bc instances have finished in round ", r)
            # print(self.bc_instances[sid + 'PCBC' + str(r)].keys())
            for i in self.bc_instances[sid + 'PCBC' + str(r)].keys():
                (_, root, sigs) = self.bc_instances[sid + 'PCBC' + str(r)][i]
                values[i] = sid + 'PCBC' + str(r), i, root, sigs
            vacs_input.put(values)

            def vaba_predicate(m):
                counter = 0
                if type(m) is list:
                    if len(m) == N:
                        for i in range(N):
                            if m[i] is not None:
                                counter += 1
                return True if counter >= N - f else False

            if self.debug:
                mvba_thread = Greenlet(speedmvba, sid + 'MVBA' + str(r), pid, N, f,
                                       self.sPK, self.sSK, self.sPK2s, self.sSK2,
                                       vacs_input.get, vacs_output.put_nowait,
                                       vacs_recv.get, vacs_send, vaba_predicate, self.logger)
            else:
                mvba_thread = Greenlet(speedmvba, sid + 'MVBA' + str(r), pid, N, f,
                                       self.sPK, self.sSK, self.sPK2s, self.sSK2,
                                       vacs_input.get, vacs_output.put_nowait,
                                       vacs_recv.get, vacs_send, vaba_predicate)

            mvba_thread.start()

        # N instances of PRBC
        for j in range(N):
            # print(self.id, "start to set up PCBC %d" % j)
            _setup_pcbc(j)

        # One instance of (validated) ACS
        # print("start to set up VACS")
        _setup_vacs()
        mvbaout = (list(vacs_output.get()))

        for i in range(N):
            if mvbaout[i] is not None:
                sid, leader, root, sigs = mvbaout[i]
                #(g, value, proof) = self.bc_instances[sid][leader]
                # self.bc_instances[sid][leader] = (2, value, proof)
                self.tobe_retrieval.put((sid, leader, root))
                # self._send(-1, ('', ('RETURN', (sid, leader, value))))
        # print("-----------------------", mvbaout)
        return mvbaout
