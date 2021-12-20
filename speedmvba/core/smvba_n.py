from gevent import monkey;

from speedmvba.core.spbc_n import strongprovablebroadcast

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
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from honeybadgerbft.core.commoncoin import shared_coin
from dumbobft.core.baisedbinaryagreement import baisedbinaryagreement
# from dumbobft.core.haltingtwovalueagreement import haltingtwovalueagreement
# from mulebft.core.twovalueagreement import twovalueagreement
from dumbobft.core.consistentbroadcast import consistentbroadcast
from dumbobft.core.validators import cbc_validate
from honeybadgerbft.exceptions import UnknownTagError


class MessageTag(Enum):
    MVBA_SPBC = 'MVBA_SPBC'  # [Queue()] * N
    MVBA_ELECT = 'MVBA_ELECT'  #
    MVBA_ABA = 'MVBA_ABA'  # [Queue()] * Number_of_ABA_Iterations
    MVBA_HALT = 'MVBA_HALT'


MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('MVBA_SPBC', 'MVBA_ELECT', 'MVBA_ABA', 'MVBA_HALT'))


def recv_loop(recv_func, recv_queues):
    while True:
        sender, (tag, r, j, msg) = recv_func()
        # print("recv2", (sender, (tag, j, msg)))

        if tag not in MessageTag.__members__:
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, MessageTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]
        if tag in {MessageTag.MVBA_SPBC.value}:
            recv_queue = recv_queue[r][j]
        elif tag not in {MessageTag.MVBA_ELECT.value, MessageTag.MVBA_HALT.value}:
            recv_queue = recv_queue[r]
        try:
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            # print((sender, msg))
            traceback.print_exc(e)
        gevent.sleep(0)


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def speedmvba(sid, pid, N, f, PK, SK, PK2s, SK2, input, decide, receive, send, predicate=lambda x: True, logger=None):
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

    assert PK.k == f + 1
    assert PK.l == N

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

    # spbc_recvs = [[Queue() for _ in range(N)] for _ in range(20)]
    spbc_recvs = defaultdict(lambda: [Queue() for _ in range(N)])
    coin_recv = Queue()
    # commit_recvs = [Queue() for _ in range(N)]
    halt_recv = Queue()

    spbc_threads = [None] * N
    spbc_outputs = [Queue(1) for _ in range(N)]
    spbc_s1_list = [Queue(1) for _ in range(N)]
    s1_list = [Queue(1) for _ in range(N)]

    is_spbc_delivered = [0] * N
    is_s1_delivered = [0] * N

    Leaders = [Queue(1) for _ in range(50)]

    recv_queues = MessageReceiverQueues(
        MVBA_SPBC=spbc_recvs,
        MVBA_ELECT=coin_recv,
        MVBA_ABA=aba_recvs,
        MVBA_HALT=halt_recv

    )
    recv_loop_thred = Greenlet(recv_loop, receive, recv_queues)
    recv_loop_thred.start()

    def broadcast(o):
        # for i in range(N):
        #     send(i, o)
        send(-1, o)

    def spbc_pridict(m):
        # print("------", m)
        msg, proof, round, tag = m

        # both yes and no vote
        if round == 0:
            return 3
        L = Leaders[round].get()
        if tag == 'yn':
            """
            try:
                for (k, sig_k) in proof:
                    assert ecdsa_vrfy(PK2s[k], hash(str((sid + 'SPBC' + str(L), msg, "ECHO"))), sig_k)
            except AssertionError:
                if logger is not None: logger.info("sig L verify failed!")
                print("sig L verify failed!")
                return -1
            """
            return 1
        if tag == 'no':
            digest_no_no = hash(str((sid, L, r - 1, 'vote')))
            """
            try:
                for (k, sig_nono) in proof:
                    assert ecdsa_vrfy(PK2s[sender], digest_no_no, sig_nono)
            except AssertionError:
                if logger is not None: logger.info("sig nono verify failed!")
                print("sig nono verify failed!")
                return -2
            """
            return 2

    r = 0

    def halt():
        hasOutputed = False
        while True:
            sender, halt_msg = halt_recv.get()
            halt_tag, halt_msg = halt_msg
            if halt_tag == 'halt' and hasOutputed == False:
                """
                try:
                    # print("-----------------", halt_msg)
                    for (k, sig_k) in halt_msg[3]:
                        assert ecdsa_vrfy(PK2s[k], hash(str((sid + 'SPBC' + str(halt_msg[0]), halt_msg[2], "FINAL"))),
                                          sig_k)
                except AssertionError:
                    if logger is not None: logger.info("vote Signature failed!")
                    print("vote Signature failed!")
                    continue
                """
                broadcast(('MVBA_HALT', r, r, ("halt", halt_msg)))
                # try:
                # print(pid, sid, "halt here 1")
                #try:
                # print(pid, halt_msg[2][0])
                decide(halt_msg[2][0])
                if logger is not None: logger.info("round %d smvba decide in halt %f" % (r, time.time()))
                # except:
                #     print("1 can not")
                #     pass
                return 2

    halt_recv_thred = gevent.Greenlet(halt)
    halt_recv_thred.start()
    while True:
        """ 
        Setup the sub protocols Input Broadcast SPBCs"""
        for j in range(N):
            def make_spbc_send(j, r):  # this make will automatically deep copy the enclosed send func
                def spbc_send(k, o):
                    """SPBC send operation.
                    :param k: Node to send.
                    :param o: Value to send.
                    """
                    # print("node", pid, "is sending", o[0], "to node", k, "with the leader", j)
                    send(k, ('MVBA_SPBC', r, j, o))

                return spbc_send

            # Only leader gets input
            spbc_input = my_spbc_input.get if j == pid else None
            spbc = gevent.spawn(strongprovablebroadcast, sid + 'SPBC' + str(j), pid, N, f, PK2s, SK2, j,
                                spbc_input, spbc_s1_list[j].put_nowait, spbc_recvs[r][j].get, make_spbc_send(j, r),
                                r, logger, spbc_pridict)
            # cbc.get is a blocking function to get cbc output
            # cbc_outputs[j].put_nowait(cbc.get())
            spbc_threads[j] = spbc
            # gevent.sleep(0)
            # print(pid, "spbc start in round ", r)

        """ 
        Setup the sub protocols permutation coins"""

        def coin_bcast(o):
            """Common coin multicast operation.
            :param o: Value to multicast.
            """
            broadcast(('MVBA_ELECT', r, 'leader_election', o))

        # permutation_coin = shared_coin(sid + 'PERMUTE', pid, N, f,
        #                               PK, SK, coin_bcast, coin_recv.get, single_bit=False)

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
            global my_msg
            v = input()
            my_msg = v

            if logger != None:
                logger.info("MVBA %s get input at %s" % (sid, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]))
            # print("node %d gets VABA input %s" % (pid, v[0]))

            my_spbc_input.put_nowait((v, "null", 0, "first"))
            # print(v[0])

        if r == 0:
            gevent.spawn(wait_for_input)

        def get_spbc_s1(leader):
            sid, pid, msg, sigmas1 = spbc_s1_list[leader].get()
            # print(sid, pid, "finish pcbc in round", r)
            if s1_list[leader].empty() is not True:
                s1_list[leader].get()

            s1_list[leader].put_nowait((msg, sigmas1))
            is_s1_delivered[leader] = 1

        spbc_s1_threads = [gevent.spawn(get_spbc_s1, node) for node in range(N)]

        wait_spbc_signal = Event()
        wait_spbc_signal.clear()

        def wait_for_spbc_to_continue(leader):
            # Receive output from CBC broadcast for input values
            msg, sigmas2 = spbc_threads[leader].get()
            # print("spbc finished, and the msg is", msg[0])
            if predicate(msg[0]):
                try:
                    if spbc_outputs[leader].empty() is not True:
                        spbc_outputs[leader].get()
                    spbc_outputs[leader].put_nowait((msg, sigmas2))
                    is_spbc_delivered[leader] = 1
                    if sum(is_spbc_delivered) >= N - f:
                        wait_spbc_signal.set()
                except:
                    pass
            else:
                pass
                # print("-----------------------predicate no")

        spbc_out_threads = [gevent.spawn(wait_for_spbc_to_continue, node) for node in range(N)]

        wait_spbc_signal.wait()
        # print("Node %d finishes n-f SPBC" % pid)
        # print(is_spbc_delivered)

        """
        Run a Coin instance to elect the leaders
        """
        time.sleep(0.1)
        seed = int.from_bytes(hash(sid), byteorder='big') % (2 ** 10 - 1)

        # seed = permutation_coin('permutation')  # Block to get a random seed to permute the list of nodes

        # print("coin has a seed:", seed)
        Leader = seed % N
        Leaders[r].put(Leader)
        if is_spbc_delivered[Leader] == 1:
            msg, s2 = spbc_outputs[Leader].get()
            halt = (Leader, 2, msg, s2)
            broadcast(('MVBA_HALT', r, pid, ("halt", halt)))
            # try:
            # print(pid, sid, "halt here 2")
            decide(msg[0])
            if logger is not None: logger.info("round %d smvba decide in shortcut. %f" % (r, time.time()))
            #except:
            #    print("2 can not")
            #    pass
            return 2
        if is_s1_delivered[Leader] == 1:
            msg, s1 = s1_list[Leader].queue[0]
            prevote = (Leader, 1, msg, s1)
            # print(pid, sid, "prevote in round ", r)
        else:
            digest_no = hash(str((sid, Leader, r, 'pre')))
            # digest_no = PK1.hash_message(str((sid, Leader, r, 'pre')))
            prevote = (Leader, 0, "bottom", ecdsa_sign(SK2, digest_no))
            # prevote = (Leader, 0, "bottom", SK1.sign(digest_no))
            # print(pid, sid, "prevote no in round ", r)
        broadcast(('MVBA_ABA', r, r, ('prevote', prevote)))
        prevote_no_shares = dict()
        vote_yes_shares = dict()
        vote_no_shares = dict()
        while True:
            hasVoted = False
            hasOutputed = False

            sender, aba_msg = aba_recvs[r].get()
            aba_tag, vote_msg = aba_msg
            if aba_tag == 'prevote' and hasVoted == False:

                digest_no = hash(str((sid, Leader, r, 'pre')))
                vote_yes_msg = 0
                # prevote no
                if vote_msg[1] != 1:
                    # print(pid, "get prevote no in round", r)
                    try:
                        assert vote_msg[0] == Leader
                        # assert (ecdsa_vrfy(PK2s[sender], digest_no, vote_msg[3]))
                        # assert (PK1.verify_share(vote_msg[3], sender, digest_no) == 1)
                    except AssertionError:
                        if logger is not None: logger.info("pre-vote no failed!")
                        print("pre-vote no failed!")
                        continue
                    prevote_no_shares[sender] = vote_msg[3]
                    if len(prevote_no_shares) == N - f:
                        sigmas_no = tuple(list(prevote_no_shares.items())[:N - f])
                        digest_no_no = hash(str((sid, Leader, r, 'vote')))
                        vote = (Leader, 0, "bottom", sigmas_no, ecdsa_sign(SK2, digest_no_no))
                        broadcast(('MVBA_ABA', r, r, ('vote', vote)))
                        # print(pid, "vote no in round", r)
                        hasVoted = True

                elif vote_msg[1] == 1:
                    try:
                        assert vote_msg[0] == Leader
                        # for (k, sig_k) in vote_msg[3]:
                        #     assert ecdsa_vrfy(PK2s[k], hash(str((sid + 'SPBC' + str(Leader), vote_msg[2], "ECHO"))),
                        #                       sig_k)
                    except AssertionError:
                        if logger is not None: logger.info("pre-vote Signature failed!")
                        print("pre-vote Signature failed!")
                        continue
                    pii = hash(str((sid + 'SPBC' + str(Leader), vote_msg[2], "FINAL")))
                    vote = (Leader, 1, vote_msg[2], vote_msg[3], ecdsa_sign(SK2, pii))
                    broadcast(('MVBA_ABA', r, r, ('vote', vote)))
                    # print(pid, "vote yes in round", r)
                    hasVoted = True

            # vote yes
            if aba_tag == 'vote' and hasOutputed == False:
                if vote_msg[1] == 1:
                    if vote_msg[0] != Leader:
                        print("wrong Leader")
                        if logger is not None: logger.info("wrong Leader")
                    """
                    try:
                        for (k, sig_k) in vote_msg[3]:
                            assert ecdsa_vrfy(PK2s[k], hash(str((sid + 'SPBC' + str(Leader), vote_msg[2], "ECHO"))),
                                              sig_k)
                        # assert PK1.verify_signature(vote_msg[3], PK1.hash_message(str((sid + 'SPBC' + str(Leader), vote_msg[2], "ECHO"))))
                        assert ecdsa_vrfy(PK2s[sender], hash(str((sid + 'SPBC' + str(Leader), vote_msg[2], "FINAL"))),
                                          vote_msg[4])
                    except AssertionError:
                        if logger is not None: logger.info("vote Signature failed!")
                        print("vote Signature failed!")
                        continue
                    """
                    vote_yes_shares[sender] = vote_msg[4]
                    vote_yes_msg = vote_msg[2]
                    # 2f+1 vote yes
                    if len(vote_yes_shares) == N - f:
                        hasOutputed = True

                        halt_msg = (Leader, 2, vote_msg[2], tuple(list(vote_yes_shares.items())[:N - f]))
                        broadcast(('MVBA_HALT', r, pid, ("halt", halt_msg)))
                        # print(pid, sid, "halt here 3")
                        if logger is not None: logger.info("round %d smvba decide in vote yes %f" % (r, time.time()))
                        decide(vote_msg[2][0])
                        return 1
                # vote no
                if vote_msg[1] == 0:
                    if vote_msg[0] != Leader:
                        print("wrong Leader")
                        if logger is not None: logger.info("wrong Leader")
                    """
                    try:
                        # vrify sigmas_no
                        for (k, sig_k) in vote_msg[3]:
                            assert ecdsa_vrfy(PK2s[k], hash(str((sid, Leader, r, 'pre'))), sig_k)

                    except AssertionError:
                        if logger is not None: logger.info("vote no failed!")
                        print(pid, "vote no failed! sigmas in round", r)
                        continue
                    
                    try:
                        # vrify no_no
                        digest_no_no = hash(str((sid, Leader, r, 'vote')))
                        assert ecdsa_vrfy(PK2s[sender], digest_no_no, vote_msg[4])
                    except AssertionError:
                        if logger is not None: logger.info("vote no failed!")

                        print("vote no failed!, digest_no_no, in round", r)
                        continue
                    """
                    vote_no_shares[sender] = vote_msg[4]
                    if len(vote_no_shares) == N - f:
                        pis = tuple(list(vote_no_shares.items())[:N - f])
                        # print(pid, sid, "n-f no vote, move to next round with in round", r)
                        my_spbc_input.put_nowait((my_msg, pis, r, 'no'))
                        # my_spbc_input.put_nowait(my_msg)
                        r += 1
                        # r = r % 10
                        break
                # both vote no and vote yes
                if (len(vote_no_shares) > 0) and (len(vote_yes_shares) > 0):
                    # print("both vote no and vote yes, move to next round with")
                    my_spbc_input.put_nowait((vote_yes_msg, vote_msg[3], r, 'yn'))
                    # print("------------------------------------", vote_yes_msg)
                    # my_spbc_input.put_nowait(vote_yes_msg)
                    r += 1
                    # r = r % 10
                    break