from gevent import monkey;

from speedmbva.core.spbc import strongprovablebroadcast

monkey.patch_all(thread=False)
import hashlib
import pickle

import copy
import time
import traceback
from datetime import datetime
import gevent
import numpy as np
from collections import namedtuple
from gevent import Greenlet
from gevent.event import Event
from enum import Enum
from collections import defaultdict
from gevent.queue import Queue
from crypto.threshsig.boldyreva import TBLSPrivateKey, TBLSPublicKey
from honeybadgerbft.core.commoncoin import shared_coin
from dumbobft.core.baisedbinaryagreement import baisedbinaryagreement
#from dumbobft.core.haltingtwovalueagreement import haltingtwovalueagreement
#from mulebft.core.twovalueagreement import twovalueagreement
from dumbobft.core.consistentbroadcast import consistentbroadcast
from dumbobft.core.validators import cbc_validate
from honeybadgerbft.exceptions import UnknownTagError



class MessageTag(Enum):
    MVBA_SPBC = 'MVBA_SPBC'               # [Queue()] * N
    MVBA_ELECT = 'MVBA_ELECT'           #
    MVBA_ABA = 'MVBA_ABA'               # [Queue()] * Number_of_ABA_Iterations


MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('MVBA_SPBC', 'MVBA_ELECT', 'MVBA_ABA'))


def recv_loop(recv_func, recv_queues):
    while True:
        sender, (tag, j, msg) = recv_func()
        # print("recv2", (sender, (tag, j, msg[0])))

        if tag not in MessageTag.__members__:
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, MessageTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]
        if tag not in {MessageTag.MVBA_ELECT.value}:
            recv_queue = recv_queue[j]
        try:
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            # print((sender, msg))
            traceback.print_exc(e)
        gevent.sleep(0)

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def speedmvba(sid, pid, N, f, PK, SK, PK1, SK1, PK2s, SK2, input, decide, receive, send, predicate=lambda x: True, logger=None):
    """Multi-valued Byzantine consensus. It takes an input ``vi`` and will
    finally writes the decided value into ``decide`` channel.

    :param sid: session identifier
    :param pid: my id number
    :param N: the number of parties
    :param f: the number of byzantine parties
    :param PK: ``boldyreva.TBLSPublicKey`` with threshold f+1
    :param SK: ``boldyreva.TBLSPrivateKey`` with threshold f+1
    :param PK1: ``boldyreva.TBLSPublicKey`` with threshold n-f
    :param SK1: ``boldyreva.TBLSPrivateKey`` with threshold n-f
    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
    :param input: ``input()`` is called to receive an input
    :param decide: ``decide()`` is eventually called
    :param receive: receive channel
    :param send: send channel
    :param predicate: ``predicate()`` represents the externally validated condition
    """

    # print("Starts to run validated agreement...")

    assert PK.k == f+1
    assert PK.l == N
    assert PK1.k == N-f
    assert PK1.l == N

    """ 
    """
    """ 
    Some instantiations
    """
    """ 
    """

    my_spbc_input = Queue(1)

    vote_recvs = defaultdict(lambda: Queue())
    aba_recvs = defaultdict(lambda: Queue())

    spbc_recvs = [Queue() for _ in range(N)]
    coin_recv = Queue()
    commit_recvs = [Queue() for _ in range(N)]

    spbc_threads = [None] * N
    spbc_outputs = [Queue(1) for _ in range(N)]
    spbc_s1_list = [Queue(1) for _ in range(N)]
    s1_list = [Queue(1) for _ in range(N)]

    is_spbc_delivered = [0] * N
    is_s1_delivered = [0] * N

    prevote_no_shares = dict()
    vote_yes_shares = dict()
    vote_no_shares = dict()

    recv_queues = MessageReceiverQueues(
        MVBA_SPBC=spbc_recvs,
        MVBA_ELECT=coin_recv,
        MVBA_ABA=aba_recvs

    )
    recv_loop_thred = Greenlet(recv_loop, receive, recv_queues)
    recv_loop_thred.start()

    def broadcast(o):
        for i in range(N):
            send(i, o)
        #send(-1, o)

    r = 0
    while True:
        """ 
        Setup the sub protocols Input Broadcast SPBCs"""

        for j in range(N):

            def make_spbc_send(j): # this make will automatically deep copy the enclosed send func
                def spbc_send(k, o):
                    """SPBC send operation.
                    :param k: Node to send.
                    :param o: Value to send.
                    """
                    # print("node", pid, "is sending", o[0], "to node", k, "with the leader", j)
                    send(k, ('MVBA_SPBC', j, o))
                return spbc_send

            # Only leader gets input
            spbc_input = my_spbc_input.get if j == pid else None
            spbc = gevent.spawn(strongprovablebroadcast, sid + 'SPBC' + str(j),  pid, N, f, PK1, SK1, j,
                               spbc_input, spbc_s1_list[j].put_nowait, spbc_recvs[j].get, make_spbc_send(j), logger)
            # cbc.get is a blocking function to get cbc output
            #cbc_outputs[j].put_nowait(cbc.get())
            spbc_threads[j] = spbc
            # gevent.sleep(0)
            # print(pid, "spbc start in round ", r)

        """ 
        Setup the sub protocols permutation coins"""

        def coin_bcast(o):
            """Common coin multicast operation.
            :param o: Value to multicast.
            """
            broadcast(('MVBA_ELECT', 'leader_election', o))

        permutation_coin = shared_coin(sid + 'PERMUTE', pid, N, f,
                                   PK, SK, coin_bcast, coin_recv.get, single_bit=False)

        # print(pid, "coin share start")
        # False means to get a coin of 256 bits instead of a single bit

        """ 
        """
        """ 
        Start to run consensus
        """
        """ 
        """

        """ 
        Run n SPBC instance to consistently broadcast input values
        """

        # cbc_values = [Queue(1) for _ in range(N)]

        def wait_for_input():
            v = input()
            if logger != None:
                logger.info("MVBA %s get input at %s" % (sid, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]))
            # print("node %d gets VABA input %s" % (pid, v[0]))

            my_spbc_input.put_nowait(v)
            # print(v[0])
        if r == 0:
            gevent.spawn(wait_for_input)

        def get_spbc_s1(leader):
            if r == 0:
                sid, pid, msg, sigmas1 = spbc_s1_list[leader].get()
            else:
                sid, pid, (msg, proof), sigmas1 = spbc_s1_list[leader].get()
            if s1_list[leader].empty():
                s1_list[leader].put_nowait((msg, sigmas1))
                is_s1_delivered[leader] = 1

        spbc_s1_threads = [gevent.spawn(get_spbc_s1, node) for node in range(N)]

        wait_spbc_signal = Event()
        wait_spbc_signal.clear()

        def wait_for_spbc_to_continue(leader):
            # Receive output from CBC broadcast for input values
            if r ==0:
                msg, sigmas2 = spbc_threads[leader].get()
            else:
                (msg, proof), sigmas2 = spbc_threads[leader].get()

            if predicate(msg):
                try:
                    if spbc_outputs[leader].empty():
                        spbc_outputs[leader].put_nowait((msg, sigmas2))
                        is_spbc_delivered[leader] = 1
                        if sum(is_spbc_delivered) >= N - f:
                            wait_spbc_signal.set()
                except:
                    pass
                # print("Node %d finishes CBC for Leader %d" % (pid, leader) )
                # print(is_cbc_delivered)

        spbc_out_threads = [gevent.spawn(wait_for_spbc_to_continue, node) for node in range(N)]

        wait_spbc_signal.wait()
        # print("Node %d finishes n-f SPBC" % pid)
        # print(is_spbc_delivered)



        """
        Run a Coin instance to elect the leaders
        """

        seed = int.from_bytes(hash(sid), byteorder='big') % (2**10 - 1)

        # seed = permutation_coin('permutation')  # Block to get a random seed to permute the list of nodes

        # print("coin has a seed:", seed)
        Leader = seed % N

        print(Leader)
        if is_spbc_delivered[Leader] ==1:
            msg, s2 = spbc_outputs[Leader].get()
            broadcast(('MVBA_ABA', r, ("halt", msg)))
            decide(msg)
            return 2
        if is_s1_delivered[Leader] == 1:
            msg, s1 = s1_list[Leader].queue[0]
            prevote = (Leader, 1, msg, s1)
        else:
            digest_no = PK1.hash_message(str((sid, Leader, r, 'pre')))

            prevote = (Leader, 0, "bottom", SK1.sign(digest_no))

        broadcast(('MVBA_ABA', r, ('prevote', prevote)))

        while True:

            hasVoted = False
            hasOutputed = False

            sender, aba_msg = aba_recvs[r].get()
            aba_tag, vote_msg = aba_msg
            if aba_tag == 'prevote' and hasVoted == False:
                digest_no = PK1.hash_message(str((sid, Leader, r, 'pre')))

                # prevote no
                if vote_msg[1] != 1:
                    try:
                        assert vote_msg[0] == Leader
                        assert (PK1.verify_share(vote_msg[3], sender, digest_no) == 1)
                    except AssertionError:
                        if logger is not None: logger.info("pre-vote no failed!")
                        print("pre-vote no failed!")
                        continue
                    prevote_no_shares[sender] = vote_msg[3]
                    if len(prevote_no_shares) == N - f:
                        sigmas_no = PK1.combine_shares(prevote_no_shares)
                        digest_no_no = PK1.hash_message(str((sid, Leader, r, 'vote')))
                        vote = (Leader, 0, "bottom", sigmas_no, SK1.sign(digest_no_no))
                        broadcast(('MVBA_ABA', r, ('vote', vote)))
                        hasVoted = True

                elif vote_msg[1] == 1:
                    try:
                        assert vote_msg[0] == Leader
                        assert PK1.verify_signature(vote_msg[3], PK1.hash_message(str((sid + 'SPBC' + str(Leader), vote_msg[2], "ECHO"))))
                    except AssertionError:
                        if logger is not None: logger.info("pre-vote Signature failed!")
                        print("pre-vote Signature failed!")
                        continue
                    pii = PK1.hash_message(str((sid + 'SPBC' + str(Leader), vote_msg[2], "FINAL")))
                    vote = (Leader, 1, vote_msg[2], vote_msg[3], SK1.sign(pii))
                    broadcast(('MVBA_ABA', r, ('vote', vote)))
                    hasVoted = True

            # vote yes
            if aba_tag == 'vote' and hasOutputed == False:
                if vote_msg[1] == 1:
                    if vote_msg[0] != Leader:
                        print("wrong Leader")
                        if logger is not None: logger.info("wrong Leader")
                    try:
                        assert PK1.verify_signature(vote_msg[3], PK1.hash_message(str((sid + 'SPBC' + str(Leader), vote_msg[2], "ECHO"))))
                        assert PK1.verify_share(vote_msg[4], sender, PK1.hash_message(str((sid + 'SPBC' + str(Leader), vote_msg[2], "FINAL"))))
                    except AssertionError:
                        if logger is not None: logger.info("vote Signature failed!")
                        print("vote Signature failed!")
                        continue
                    vote_yes_shares[sender] = vote_msg[4]
                    # 2f+1 vote yes
                    if len(vote_yes_shares) == N - f:
                        hasOutputed = True
                        broadcast(('MVBA_ABA', r, ("halt", vote_msg[2])))
                        decide(vote_msg[2])
                # vote no
                if vote_msg[1] == 0:
                    if vote_msg[0] != Leader:
                        print("wrong Leader")
                        if logger is not None: logger.info("wrong Leader")
                    try:
                        # vrify sigmas_no
                        assert PK1.verify_signature(vote_msg[3], PK1.hash_message(str((sid + 'SPBC' + str(Leader), vote_msg[2], "ECHO"))))
                        # vrify no_no
                        digest_no_no = PK1.hash_message(str((sid, Leader, r, 'vote')))
                        assert PK1.verify_share(vote_msg[4], sender, digest_no_no)
                    except AssertionError:
                        if logger is not None: logger.info("vote no failed!")
                        print("vote no failed!")
                        continue
                    vote_no_shares[sender] = vote_msg[4]
                    if len(vote_no_shares) == N - f:
                        pis = PK1.combine_shares(vote_no_shares)
                        print("n-f no vote, move to next round with", (vote_msg[2], pis))
                        my_spbc_input.put_nowait((vote_msg[2], pis))
                        r += 1
                        break
                # both vote no and vote yes
                if (len(vote_no_shares) > 0) and (len(vote_yes_shares) > 0):
                    print("both vote no and vote yes, move to next round with",(vote_msg[2], vote_msg[3]))
                    my_spbc_input.put_nowait((vote_msg[2], vote_msg[3]))
                    r += 1
                    break
