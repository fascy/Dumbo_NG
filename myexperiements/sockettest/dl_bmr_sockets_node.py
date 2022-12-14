import gevent
from gevent import monkey, Greenlet;

from dispersedledger.core.bc_mvba import BM
from dispersedledger.core.recover import RECOVER

monkey.patch_all(thread=False)


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


class DL2Node (BM):

    def __init__(self, sid, id, S, Bfast, Bacs, N, f,
                 bft_from_server1: Callable, bft_to_client1: Callable,bft_from_server2: Callable, bft_to_client2: Callable, ready: mpValue, stop: mpValue, K=3, mode='debug', mute=False, tx_buffer=None):
        self.sPK, self.sPK1, self.sPK2s, self.ePK, self.sSK, self.sSK1, self.sSK2, self.eSK = load_key(id, N)
        #self.recv_queue = recv_q
        #self.send_queue = send_q
        self.bft_to_client1 = bft_to_client1
        self.bft_from_server1 = bft_from_server1

        self.bft_to_client2 = bft_to_client2
        self.bft_from_server2 = bft_from_server2
        self.ready = ready
        self.stop = stop
        self.mode = mode
        BM.__init__(self, sid, id, max(int(Bfast), 1), N, f,
                       self.sPK, self.sSK, self.sPK1, self.sSK1, self.sPK2s, self.sSK2,
                       send1=None, send2=None, recv=None, K=K, mute=mute)

        # Hotstuff.__init__(self, sid, id, max(S, 200), max(int(Bfast), 1), N, f, self.sPK, self.sSK, self.sPK1, self.sSK1, self.sPK2s, self.sSK2, self.ePK, self.eSK, send=None, recv=None, K=K, mute=mute)

    def prepare_bootstrap(self):
        self.logger.info('node id %d is inserting dummy payload TXs' % (self.id))
        tx = tx_generator(250)  # Set each dummy TX to be 250 Byte
        if self.mode == 'test' or 'debug': #K * max(Bfast * S, Bacs)
            k = 0
            for r in range(max(self.B * self.K, 1)):
                suffix = hex(self.id) + hex(r) + ">"
                BM.submit_tx(self, tx[:-len(suffix)] + suffix)
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

        self._send1 = lambda j, o: self.bft_to_client1((j, o))
        self._recv = lambda: self.bft_from_server1()
        self._send2 = lambda j, o: self.bft_to_client2((j, o))
        recv2 = lambda: self.bft_from_server2()


        self.prepare_bootstrap()

        while not self.ready.value:
            time.sleep(1)
            #gevent.sleep(1)

        recover = RECOVER(self.sid, self.id, self.B, self.N, self.f,
                         self.sPK, self.sSK, self.sPK1, self.sSK1, self.sPK2s, self.sSK2,
                         recv=recv2, K=self.K, mute=self.mute,logger=self.logger)

        recover.start()
        self.run_bft()

        recover.join()

        self.stop.value = True
