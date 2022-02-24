import gevent
from gevent import monkey, Greenlet; monkey.patch_all(thread=False)

from dumbong.core.ng import Dumbo_NG

from typing import List, Callable
import os
import pickle
from gevent import time, monkey
from myexperiements.sockettest.make_random_tx import tx_generator
from coincurve import PrivateKey, PublicKey
from multiprocessing import Value as mpValue, Queue as mpQueue, Process

def load_key(id, N):

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sPK.key', 'rb') as fp:
        sPK = pickle.load(fp)

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sPK1.key', 'rb') as fp:
        sPK1 = pickle.load(fp)

    sPK2s = []
    for i in range(N):
        with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sPK2-' + str(i) + '.key', 'rb') as fp:
            sPK2s.append(PublicKey(pickle.load(fp)))

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'ePK.key', 'rb') as fp:
        ePK = pickle.load(fp)

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sSK-' + str(id) + '.key', 'rb') as fp:
        sSK = pickle.load(fp)

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sSK1-' + str(id) + '.key', 'rb') as fp:
        sSK1 = pickle.load(fp)

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sSK2-' + str(id) + '.key', 'rb') as fp:
        sSK2 = PrivateKey(pickle.load(fp))

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'eSK-' + str(id) + '.key', 'rb') as fp:
        eSK = pickle.load(fp)

    return sPK, sPK1, sPK2s, ePK, sSK, sSK1, sSK2, eSK


class NGNode (Dumbo_NG):

    def __init__(self, sid, id, S, T, Bfast, Bacs, N, f,
                 bft_from_server: Callable, bft_to_client: Callable, ready: mpValue, stop: mpValue, K=3, mode='debug', mute=False, tx_buffer=None):
        self.sPK, self.sPK1, self.sPK2s, self.ePK, self.sSK, self.sSK1, self.sSK2, self.eSK = load_key(id, N)
        #self.recv_queue = recv_q
        #self.send_queue = send_q
        self.bft_from_server = bft_from_server
        self.bft_to_client = bft_to_client
        self.ready = ready
        self.stop = stop
        self.mode = mode
        Dumbo_NG.__init__(self,sid, id, max(S, 10), max(int(Bfast), 1), N, f,
                       self.sPK, self.sSK, self.sPK1, self.sSK1, self.sPK2s, self.sSK2, self.ePK, self.eSK,
                       send=None, recv=None, K=K, mute=mute)

        # Hotstuff.__init__(self, sid, id, max(S, 200), max(int(Bfast), 1), N, f, self.sPK, self.sSK, self.sPK1, self.sSK1, self.sPK2s, self.sSK2, self.ePK, self.eSK, send=None, recv=None, K=K, mute=mute)

    def prepare_bootstrap(self):
        self.logger.info('node id %d is inserting dummy payload TXs' % (self.id))
        tx = tx_generator(250)  # Set each dummy TX to be 250 Byte
        if self.mode == 'test' or 'debug': #K * max(Bfast * S, Bacs)
            k = 0
            for _ in range(self.K + 1):
                for r in range(max(self.B * self.SLOTS_NUM, 1)):
                    suffix = hex(self.id) + hex(r) + ">"
                    Dumbo_NG.submit_tx(self, tx[:-len(suffix)] + suffix)
                    # print("submit to buffer: ", tx[:-len(suffix)] + suffix)
                    k += 1
                    if r % 50000 == 0:
                        self.logger.info('node id %d just inserts 50000 TXs' % (self.id))
        else:
            pass
            # TODO: submit transactions through tx_buffer
        self.logger.info('node id %d completed the loading of dummy TXs' % (self.id))

    def run(self):

        pid = os.getpid()
        self.logger.info('node %d\'s starts to run consensus on process id %d' % (self.id, pid))

        self._send = lambda j, o: self.bft_to_client((j, o))
        self._recv = lambda: self.bft_from_server()

        self.prepare_bootstrap()

        while not self.ready.value:
            time.sleep(1)
            #gevent.sleep(1)

        self.run_bft()

        self.stop.value = True
