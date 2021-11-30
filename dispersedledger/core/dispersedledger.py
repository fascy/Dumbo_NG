import multiprocessing

from gevent import monkey;

from dispersedledger.core.PCBC import provablecbc

from speedmbva.core.smvba_e import speedmvba

monkey.patch_all(thread=False)

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


from dumbobft.core.validators import prbc_validate
from honeybadgerbft.core.honeybadger_block import honeybadger_block
from honeybadgerbft.exceptions import UnknownTagError


def set_consensus_log(id: int):
    logger = logging.getLogger("consensus-node-"+str(id))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "consensus-node-"+str(id) + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
    logger.addHandler(file_handler)
    return logger

class BroadcastTag(Enum):
    ACS_PCBC = 'ACS_PCBC'
    ACS_VACS = 'ACS_VACS'
    RETRIVAL = 'RETRIEVAL'

BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('ACS_PCBC', 'ACS_VACS', 'RETRIEVAL'))

def broadcast_receiver_loop(recv_func, recv_queues):
    while True:
        #gevent.sleep(0)
        sender, (tag, j, msg) = recv_func()
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
    """Dumbo object used to run the protocol.

        :param str sid: The base name of the common coin that will be used to
            derive a nonce to uniquely identify the coin.
        :param int pid: Node id.
        :param int B: Batch size of transactions.
        :param int N: Number of nodes in the network.
        :param int f: Number of faulty nodes that can be tolerated.
        :param TBLSPublicKey sPK: Public key of the (f, N) threshold signature
            (:math:`\mathsf{TSIG}`) scheme.
        :param TBLSPrivateKey sSK: Signing key of the (f, N) threshold signature
            (:math:`\mathsf{TSIG}`) scheme.
        :param TBLSPublicKey sPK1: Public key of the (N-f, N) threshold signature
            (:math:`\mathsf{TSIG}`) scheme.
        :param TBLSPrivateKey sSK1: Signing key of the (N-f, N) threshold signature
            (:math:`\mathsf{TSIG}`) scheme.
        :param list sPK2s: Public key(s) of ECDSA signature for all N parties.
        :param PrivateKey sSK2: Signing key of ECDSA signature.
        :param send:
        :param recv:
        :param K: a test parameter to specify break out after K rounds
        """

    def __init__(self, sid, pid, B, N, f, sPK, sSK, sPK1, sSK1, sPK2s, sSK2, send, recv, K=3, mute=False,
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
        self._send = send
        self._recv = recv
        self.logger = set_consensus_log(pid)
        self.round = 0  # Current block number
        self.transaction_buffer = Queue()
        self._per_round_recv = {}  # Buffer of incoming messages

        self.K = K

        self.s_time = 0
        self.e_time = 0
        self.txcnt = 0

        self.mute = mute
        self.debug = debug
        self.bc_instances = defaultdict(lambda: defaultdict())
        self.output_list = [multiprocessing.Queue() for _ in range(N)]
        self.tobe_retrieval = multiprocessing.Queue()


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

        def _recv_loop():
            """Receive messages."""
            #print("start recv loop...")
            while True:
                #gevent.sleep(0)
                try:
                    (sender, (r, msg) ) = self._recv()
                    #self.logger.info('recv1' + str((sender, o)))
                    # Maintain an *unbounded* recv queue for each epoch
                    if r not in self._per_round_recv:
                        self._per_round_recv[r] = Queue()
                    # Buffer this message
                    self._per_round_recv[r].put_nowait((sender, msg))
                except:
                    continue

        self._recv_thread = Greenlet(_recv_loop)
        self._recv_thread.start()

        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))

        while True:

            # For each round...
            #gevent.sleep(0)

            start = time.time()

            r = self.round
            if r not in self._per_round_recv:
                self._per_round_recv[r] = Queue()

            # Select B transactions (TODO: actual random selection)
            tx_to_send = []
            for _ in range(self.B):
                tx_to_send.append(self.transaction_buffer.get_nowait())

            def _make_send(r):
                def _send(j, o):
                    self._send(j, (r, o))
                return _send

            send_r = _make_send(r)
            recv_r = self._per_round_recv[r].get
            new_tx = self._run_BC_MVBA_round(r, tx_to_send, send_r, recv_r)

            if self.logger != None:
                tx_cnt = str(new_tx).count("PCBC")
                self.txcnt += tx_cnt
                self.logger.info('Node %d Delivers ACS Block in Round %d with having %d TXs' % (self.id, r, tx_cnt))
                print('Node %d Delivers ACS Block in Round %d with having %d TXs, %d in total' % (self.id, r, tx_cnt, self.txcnt))

            end = time.time()

            if self.logger != None:
                self.logger.info('ACS Block Delay at Node %d: ' % self.id + str(end - start))
                print('ACS Block Delay at Node %d: ' % self.id + str(end - start))
            # Put undelivered but committed TXs back to the backlog buffer
            #for _tx in tx_to_send:
            #    if _tx not in new_tx:
            #        self.transaction_buffer.put_nowait(_tx)

            # print('buffer at %d:' % self.id, self.transaction_buffer)
            #if self.logger != None:
            #    self.logger.info('Backlog Buffer at Node %d:' % self.id + str(self.transaction_buffer))

            self.round += 1     # Increment the round
            if self.round >= self.K:
                break   # Only run one round for now

        if self.logger != None:
            self.e_time = time.time()
            self.logger.info("node %d breaks in %f seconds with total delivered Txs %d" % (self.id, self.e_time-self.s_time, self.txcnt))
        else:
            print("node %d breaks" % self.id)

        #self._recv_thread.join(timeout=2)

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

        pcbc_recvs = [Queue() for _ in range(N)]
        vacs_recv = Queue()
        re_recvs = [Queue() for _ in range(N)]

        my_pcbc_input = Queue(1)

        # pcbc_outputs = [Queue(1) for _ in range(N)]
        # pcbc_outputs = defaultdict(lambda: defaultdict())

        vacs_input = Queue(1)
        vacs_output = Queue(1)

        recv_queues = BroadcastReceiverQueues(
            ACS_PCBC=pcbc_recvs,
            ACS_VACS=vacs_recv,
            RETRIEVAL=re_recvs
        )

        bc_recv_loop_thread = Greenlet(broadcast_receiver_loop, recv, recv_queues)
        bc_recv_loop_thread.start()

        def _setup_pcbc(j):
            """Setup the sub protocols RBC, BA and common coin.
            :param int j: Node index for which the setup is being done.
            """

            def pcbc_send(k, o):
                """Reliable send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                send(k, ('ACS_PCBC', j, o))

            # Only leader gets input
            if pid == j:
                # print(j, json.dumps(tx_to_send))
                my_pcbc_input.put(json.dumps(tx_to_send))
                pcbc_input = my_pcbc_input.get
            else: pcbc_input = None

            if self.debug:
                pcbc_thread = gevent.spawn(provablecbc, sid + 'PCBC' + str(r) + str(j), pid, N, f,
                                           self.sPK2s, self.sSK2, j,
                                           pcbc_input, pcbc_recvs[j].get, pcbc_send, self.logger)
            else:
                pcbc_thread = gevent.spawn(provablecbc, sid + 'PCBC' + str(r) + str(j), pid, N, f,
                                           self.sPK2s, self.sSK2, j,
                                           pcbc_input, pcbc_recvs[j].get, pcbc_send, self.logger)

            def wait_for_prbc_output():
                value, proof = pcbc_thread.get()
                (chunk, proof, root) = value
                self.bc_instances[sid + 'PCBC' + str(r)][j] = 1, value, proof
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
            print("N - f bc instances have finished in round ", r)
            # print(self.bc_instances[sid + 'PCBC' + str(r)].keys())
            for i in self.bc_instances[sid + 'PCBC' + str(r)].keys():
                (_, (chunk, proof, root), sigs) = self.bc_instances[sid + 'PCBC' + str(r)][i]
                values[i] = sid + 'PCBC' + str(r), i, root, sigs
            vacs_input.put(values)

            def make_vaba_predicate():
                def vaba_predicate(m):
                    counter = 0
                    if type(m) is list:
                        if len(m) == N:
                            for i in range(N):
                                if m[i] is not None:
                                    counter += 1
                    return True if counter >= N - f else False

                return vaba_predicate

            if self.debug:
                mvba_thread = Greenlet(speedmvba, sid+'MVBA'+str(r), pid, N, f,
                                   self.sPK, self.sSK, self.sPK2s, self.sSK2,
                                   vacs_input.get, vacs_output.put_nowait,
                                   vacs_recv.get, vacs_send, make_vaba_predicate(), self.logger)
            else:
                mvba_thread = Greenlet(speedmvba, sid+'MVBA'+str(r), pid, N, f,
                                   self.sPK, self.sSK, self.sPK2s, self.sSK2,
                                   vacs_input.get, vacs_output.put_nowait,
                                   vacs_recv.get, vacs_send, make_vaba_predicate())
            mvba_thread.start()

        # N instances of PRBC
        for j in range(N):
            # print(self.id, "start to set up PCBC %d" % j)
            _setup_pcbc(j)

        # One instance of (validated) ACS
        print("start to set up VACS")
        _setup_vacs()
        mvbaout = (list(vacs_output.get()))
        for i in range(N):
            sid, leader, root, sigs = mvbaout[i]
            (g, value, proof) = self.bc_instances[sid][leader]
            self.bc_instances[sid][leader] = (2, value, proof)
            self.tobe_retrieval.put(sid, leader, root)

        # print("-----------------------", mvbaout)
        return mvbaout
