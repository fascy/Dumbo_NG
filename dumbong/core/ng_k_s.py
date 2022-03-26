import collections
import zlib

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


class Dumbo_NG_k_s:
    def __init__(self, sid, pid, S, B, N, f, sPK, sSK, sPK1, sSK1, sPK2s, sSK2, ePK, eSK, send, recv, K=3, countpoint=0,
                 mute=False,
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
        # self.transaction_buffer = defaultdict(lambda: collections.deque())
        self.transaction_buffer = defaultdict(lambda: gevent.queue.Queue())
        # self.transaction_buffer =[collections.deque() for _ in range(self.K)]
        self.output_list = [multiprocessing.Queue() for _ in range(N * self.K)]
        self.fast_recv = [multiprocessing.Queue() for _ in range(N * self.K)]
        self.mvba_recv = defaultdict(lambda: gevent.queue.Queue())
        self.debug = debug
        self.s_time = 0
        self.tx_cnt = 0
        self.total_tx = 0
        self.total_delay = 0
        self.count_delay = 0
        self.latency = 0
        self.a_latency = 0
        self.mute = mute
        self.threads = []
        self.txs = defaultdict(lambda: defaultdict())
        self.sigs = defaultdict(lambda: defaultdict(lambda: tuple()))
        self.sts = defaultdict(lambda: defaultdict())
        self.st_sum = 0
        self.help_count = 0
        self.op = os.getpid()
        self.ap = 0
        self.countpoint = countpoint
        self.abc_count = 0
        self.vaba_latency = 0
        self.catch_up_sum = 0
        self.catch_up_sum1 = 0
        self.catch_up_sum2 = 0
        self.epoch = 0

    def submit_tx(self, tx, j):
        """Appends the given transaction to the transaction buffer.
        :param tx: Transaction to append to the buffer.
        """
        # self.transaction_buffer[j].append(tx)
        self.transaction_buffer[j].put_nowait(tx)

    def buffer_size(self, k):
        # return len(self.transaction_buffer[k])
        return self.transaction_buffer[k].qsize()

    # Entry of the Dumbo-NG protocol
    def run_bft(self):

        """Run the Dumbo-NG protocol."""
        self.s_time = time.time()
        if self.mute:
            muted_nodes = [each * 3 + 1 for each in range(int((self.N - 1) / 3))]
            if self.id in muted_nodes:
                while True:
                    time.sleep(10)

        for i in range(self.N * self.K):
            self.sigs[i][0] = ()
            self.txs[i][0] = ""

        def _recv_loop():
            """Receive messages."""
            if os.getpid() != self.op:
                return
            print("run _recv_loop:", os.getpid())
            while True:
                try:
                    (sender, (r, msg)) = self._recv()
                    # print("in ng recv:", r, msg[0])
                    if msg[0] == 'PROPOSAL' or msg[0] == 'VOTE':
                        self.fast_recv[int(msg[1][6:])].put_nowait((sender, msg))
                    else:
                        if r < self.epoch:
                            continue
                        self.mvba_recv[r].put_nowait((sender, msg[2]))
                except Exception as e:
                    # print(e)
                    continue

                gevent.sleep(0.001)

        # This process tracks the recent progress of broadcasts and run a seuqnce of validated agreement
        # such that it can pack all broadcasted transactions into the ledger
        def _finalize_output():

            # epoch = 0
            sid = self.sid
            pid = self.id
            N = self.N
            K = self.K
            f = self.f

            prev_view = [0] * (N * K)
            cur_view = [0] * (N * K)

            recent_digest = defaultdict((lambda: defaultdict()))

            # per_epoch_recv = {}  # Buffer of incoming messages
            self.op = os.getpid()

            # This method defines one validated agreement and its external validity condition
            def _run_VABA_round(tx_to_send, send, recv):
                """Run one VABA round.
                :param int r: round id
                :param tx_to_send: Transaction(s) to process.
                :param send:
                :param recv:
                """
                nonlocal sid, pid, N, K, f, prev_view, cur_view, recent_digest

                prev_view_e = copy.copy(prev_view)
                # Unique sid for each round

                vaba_input = gevent.queue.Queue(1)
                vaba_output = gevent.queue.Queue(1)
                vaba_input.put_nowait(tx_to_send)
                sid_e = sid + ':' + str(self.epoch)
                self.tx_cnt = 0

                # def make_vaba_send():
                #    def vaba_send(k, o):
                #        send(k, ('X_VABA', '', o))
                #    return vaba_send

                def make_vaba_predicate():
                    nonlocal sid, pid, N, K, f, prev_view_e, cur_view, recent_digest

                    def vaba_predicate(vj):
                        siglist = [tuple() for _ in range(N * K)]
                        (view, sigsdata, digestlist) = vj
                        # check n-f gorws
                        cnt2 = 0
                        for i in range(N):
                            for j in range(K):
                                progress = view[i * K + j] - prev_view_e[i * K + j]
                                if progress == 0:
                                    continue
                                elif progress > 0:
                                    cnt2 += 1
                                    break
                                else:
                                    print("Wrong progress --- try rollback")
                                    # print(view)
                                    # print(prev_view)
                                    return False
                        if cnt2 < N - f:
                            print("Wrong progress --- less than n-f")
                            # print(view)
                            # print(prev_view)
                            return False

                        # check all sig
                        for i in range(N):
                            for j in range(K):
                                # find tx in local first
                                if view[i * K + j] <= cur_view[i * K + j]:
                                    try:
                                        assert self.txs[i * K + j][view[i * K + j]] == digestlist[i * K + j]
                                        # print("pass predicate...1")
                                        return True
                                    except AssertionError as e:
                                        if self.logger is not None: self.logger.info(e)
                                        pass
                                    except KeyError as e:
                                        if self.logger is not None: self.logger.info(e)
                                        pass
                                # then find in hash table
                                if view[i * K + j] in recent_digest[i * K + j].keys():
                                    try:
                                        assert recent_digest[i * K + j][view[i * K + j]] == digestlist[i * K + j]
                                    except:
                                        print("inconsistent hash digest")
                                        return False
                                # have to check sig and regist in hash table
                                else:
                                    pass
                                    sid_r = sid + 'nw' + str(i * K + j)
                                    try:
                                        digest2 = digestlist[i * K + j] + hash(str((sid_r, view[i * K + j])))
                                        for item in siglist[i * K + j]:
                                            (sender, sig_p) = item
                                            assert ecdsa_vrfy(self.sPK2s[sender], digest2, sig_p)
                                            # assert ecdsa.verify(sig_p, digest2, self.sPK2[sender], curve=curve.P192)
                                    except AssertionError:
                                        if self.logger is not None: self.logger.info("ecdsa signature failed!")
                                        print("ecdsa signature failed!")
                                        return False
                                    recent_digest[i * K + j][view[i * K + j]] = digestlist[i * K + j]
                                    # print(i * self.K + j,":",len(recent_digest[i * self.K + j]))
                        # print("pass predicate...2")
                        return True

                    return vaba_predicate

                # print("vaba starts....")
                vaba_thread_r = Greenlet(speedmvba, sid_e + 'VABA' + str(self.epoch), pid, N, f,
                                         self.sPK, self.sSK, self.sPK2s, self.sSK2,
                                         vaba_input.get, vaba_output.put_nowait,
                                         recv, send, predicate=make_vaba_predicate(), logger=self.logger)

                vaba_thread_r.start()
                out = vaba_output.get()
                (view, s, txhash) = out

                # print("vaba returns....")
                def catch(v_s, v, r):
                    catchup = 0
                    gevent.sleep(0.05)
                    for k in range(self.N * self.K):
                        for t in range(v_s[k] + 1, v[k] + 1):
                            if self.txs[k][t] == "catch":
                                catchup += 1
                                if self.epoch > self.countpoint:
                                    self.catch_up_sum1 += 1
                    # print("sid: %d: %d txs batches need to catchup after 50ms in round %d, %d in total, %f " % (self.id, catchup, r, self.catch_up_sum1, self.catch_up_sum1/(self.total_tx/self.B)))
                    if self.logger != None:
                        self.logger.info(
                            "sid: %d: %d txs batches need to call help after 50ms in epoch %d, %d in total, %f " % (
                            self.id, catchup, r, self.catch_up_sum1, self.catch_up_sum1 / (self.total_tx / self.B)))

                    gevent.sleep(0.05)
                    catchup2 = 0
                    for k in range(self.N * self.K):
                        for t in range(v_s[k] + 1, v[k] + 1):
                            if self.txs[k][t] == "catch":
                                catchup2 += 1
                                if self.epoch > self.countpoint:
                                    self.catch_up_sum2 += 1
                    # print("sid: %d: %d txs batches need to catchup after 100ms in round %d, %d in total, %f " % (self.id, catchup2, r, self.catch_up_sum2, self.catch_up_sum2/(self.total_tx/self.B)))
                    if self.logger != None:
                        self.logger.info(
                            "sid: %d: %d txs batches need to call help after 100ms in epoch %d, %d in total, %f " % (
                            self.id, catchup2, r, self.catch_up_sum2, self.catch_up_sum2 / (self.total_tx / self.B)))

                self.help_count = 0
                self.st_sum = 0
                for i in range(N):
                    for j in range(K):
                        # check sigs in s[i][view[i]]
                        if cur_view[i * K + j] < view[i * K + j]:
                            # TODO: ADD PULLING BLOCK
                            for t in range(cur_view[i * K + j] + 1, view[i * K + j] + 1):
                                tx = "catch"
                                self.txs[i * K + j][t] = tx
                        for t in range(prev_view_e[i * K + j] + 1, view[i * K + j] + 1):
                            try:
                                add = self.sts[i * K + j][t]
                            except:
                                add = 0
                                self.help_count += 1
                                if self.epoch > self.countpoint + 1:
                                    self.catch_up_sum += 1
                            self.st_sum += add
                            self.tx_cnt += self.B
                if self.epoch > self.countpoint + 1:
                    # print(
                    #     "sid: %d: %d txs batches need to catchup in round %d, %d in total, %f " % (self.id, self.help_count, epoch, self.catch_up_sum, self.catch_up_sum/(self.total_tx/self.B)))
                    if self.logger != None:
                        self.logger.info("sid: %d: %d txs batches need to call help in epoch %d, %d in total, %f " % (
                        self.id, self.help_count, self.epoch,
                        self.catch_up_sum, self.catch_up_sum / (self.total_tx / self.B)))
                    gevent.spawn(catch, cur_view, view, self.epoch)
                prev_view = view
                # vaba_thread_r.kill()

            def _make_vaba_send(r):
                def _send(j, o):
                    self._send(j, (r, ('X_VABA', '', o)))

                return _send

            # only store TX batch digest and QCs of the latest 200 slots
            # and delete the old stuff from memory.
            # This allows a faster predicate method in validated agreement
            # because if a QC was recently verified by the broadcast process,
            # no need to verify signatures in it again in predicate method.
            def track_progress():
                if os.getpid() != self.op:
                    return
                while True:
                    for i in range(self.N):
                        for j in range(self.K):
                            while self.output_list[i * self.K + j].qsize() > 0:
                                out = self.output_list[i * self.K + j].get()
                                (_, s, tx, sig, st) = out

                                if s > cur_view[i * self.K + j]:
                                    cur_view[i * self.K + j] = s
                                    self.txs[i * self.K + j][s] = tx
                                    self.sigs[i * self.K + j][s] = sig
                                    self.sts[i * self.K + j][s] = st
                                    if self.epoch > 50:
                                        del_p = max(0, cur_view[i * self.K + j] - 50)
                                        try:
                                            for p in list(self.txs[i * self.K + j]):
                                                if p < del_p:
                                                    self.txs[i * self.K + j].pop(p)
                                                    self.sigs[i * self.K + j].pop(p)
                                                    self.sts[i * self.K + j].pop(p)
                                            for p in list(recent_digest[i * K + j]):
                                                if p < del_p:
                                                    self.recent_digest[i * K + j].pop(p)
                                        except Exception as err:
                                            pass
                    gevent.sleep(0.1)

            gevent.spawn(track_progress)
            vaba_input = None

            # This loop runs a sequence of validated agreement to agree on a cut of broadcasts
            # zero = time.time()
            if self.epoch == 0:
                if self.logger != None:
                    self.logger.info("*************************************************************")
                    self.logger.info("                         warm-up start                       ")
                    self.logger.info("*************************************************************")
            while True:
                # print(r, "start!")
                if self.epoch == self.countpoint + 1:
                    zero = time.time()
                    if self.logger != None:
                        self.logger.info("warm-up time: %f" % (zero-self.s_time))
                        self.logger.info("*************************************************************")
                        self.logger.info("                       warm-up finished                      ")
                        self.logger.info("*************************************************************")


                start = time.time()

                send_r = _make_vaba_send(self.epoch)
                recv_r = self.mvba_recv[self.epoch].get

                # Here wait for enough progress to start Validated agreement
                # The input is set by track_broadcast_progress() handler that processes broadcast QC
                # wait_input_signal.wait()
                # Here wait for enough progress to start Validated agreement
                while True:
                    count = [0 for _ in range(self.N)]
                    #print(self.local_view)
                    for i in range(self.N):
                        for j in range(self.K):
                            grow = cur_view[i * self.K + j] - prev_view[i * self.K + j]
                            if grow < 0:
                                count[i] = -1
                                break
                            elif grow > 0:
                                count[i] = 1
                        else:
                            continue
                        break
                    if sum(count) >= self.N - self.f and -1 not in count:
                        break
                    gevent.sleep(0)

                lview = copy.copy(cur_view)
                sig_str = pickle.dumps([self.sigs[j][lview[j]] for j in range(int(self.N * self.K))])
                # sig_str_compress = zlib.compress(sig_str)
                vaba_input = (lview, sig_str,
                                      [self.txs[j][lview[j]] for j in range(self.N * self.K)])

                start2 = time.time()
                _run_VABA_round(vaba_input, send_r, recv_r)

                end = time.time()

                if self.epoch > self.countpoint:  # Start to count statistics after some warmup
                    self.total_tx += self.tx_cnt  # Number of so-far output transactions
                    self.count_delay = end - zero # running time after warming up
                    self.latency = (((self.tx_cnt / self.B) - self.help_count) * end - self.st_sum) / (
                            (self.tx_cnt / self.B) - self.help_count)
                    # Calculate the latency of this epoch
                    self.a_latency = (self.a_latency * (
                            self.total_tx - self.tx_cnt) + self.latency * self.tx_cnt) / self.total_tx
                    # Calculate the overal average latency of all past epoches
                    self.vaba_latency = (self.vaba_latency * (self.epoch - self.countpoint) + (end - start2)) / (
                                self.epoch - self.countpoint + 1)
                if self.logger != None and self.epoch > self.countpoint:
                    self.logger.info(  # Print average delay/throughput to the execution log
                        "node: %d epoch: %d run: %f, "
                        "total delivered Txs after warm-up: %d, "
                        "average delay after warm-up: %f, "
                        " tps after warm-up: %f, "
                        "average vaba delay after warm-up: %f" %
                        (self.id, self.epoch, end - self.s_time, self.total_tx, self.a_latency,
                         self.total_tx / self.count_delay,
                         self.vaba_latency))
                    print(
                        "node: %d epoch: %d run: %f, "
                        "total delivered Txs after warm-up: %d, "
                        "average delay after warm-up: %f, "
                        " tps after warm-up: %f, "
                        "average vaba delay after warm-up: %f" %
                        (self.id, self.epoch, end - self.s_time, self.total_tx, self.a_latency,
                         self.total_tx / self.count_delay,
                         self.vaba_latency))

                if self.epoch > 2:
                    del self.mvba_recv[self.epoch - 3]
                self.epoch += 1

        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))

        def _make_send_nwabc():
            def _send(j, o):
                # print(j, o[0], o[1])
                self._send(j, ('', o))

            return _send

        # run n nwabc instances
        def abcs():
            self.ap = os.getpid()
            print("run n*k abcs:", os.getpid())
            for i in range(0, self.N):
                for j in range(self.K):
                    send = _make_send_nwabc()
                    recv = self.fast_recv[i * self.K + j].get
                    self._run_nwabc(send, recv, i, j)
            gevent.joinall(self.threads)

        # Start the agreement process and broadcast process
        self._abcs = Process(target=abcs)
        self._abcs.start()
        self._recv_output = gevent.spawn(_finalize_output)


        # Start the message handler
        self._recv_thread = gevent.spawn(_recv_loop)

        self._abcs.join(timeout=86400)

    # This process runs broadcast instances
    # and it will return the lastest progress to process via multiprocessing queues
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
                         self.transaction_buffer[j].get, self.output_list[i * self.K + j].put_nowait, recv, send,
                         self.logger, 1)
        self.threads.append(t)
