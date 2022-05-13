# for n pd instances
import traceback
import logging
import gevent
import numpy as np

from collections import namedtuple
from gevent import monkey
from gevent.event import Event
from enum import Enum
from collections import defaultdict
from gevent.queue import Queue
from honeybadgerbft.core.commoncoin import shared_coin
from honeybadgerbft.core.binaryagreement import binaryagreement
from dumbomvba.core.provabledispersal import provabledispersalbroadcast
from dumbomvba.core.rebroadcast import recastsubprotocol
from honeybadgerbft.exceptions import UnknownTagError
from crypto.threshsig.boldyreva import serialize, deserialize1




class MessageTag(Enum):
    MVBA_COIN = 'MVBA_COIN'             # Queue()
    MVBA_PD = 'MVBA_PD'         # [Queue()] * N
    MVBA_PD_FINISH = 'MVBA_PD_FINISH'
    MVBA_RC_PREPARE = 'MVBA_RC_PREPARE'
    MVBA_RC = 'MVBA_RC'
    MVBA_ABA = 'MVBA_ABA'   # [Queue()] * Number_of_ABA_Iterations
    MVBA_ABA_COIN = 'MVBA_ABA_COIN'

MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('MVBA_COIN', 'MVBA_PD', 'MVBA_PD_FINISH', 'MVBA_RC', 'MVBA_ABA',
                              'MVBA_RC_PREPARE', 'MVBA_ABA_COIN'))

def handle_mvba_messages(recv_func, recv_queues):
    x = recv_func()
    #print(x)
    sender, (tag, j, msg) = x
    # sender, (tag, j, msg) = recv_func()
    if tag not in MessageTag.__members__:
        # TODO Post python 3 port: Add exception chaining.
        # See https://www.python.org/dev/peps/pep-3134/
        raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
            tag, MessageTag.__members__.keys()))
    recv_queue = recv_queues._asdict()[tag]
    # print(tag, sender)
    if tag == MessageTag.MVBA_PD.value or tag in {MessageTag.MVBA_ABA_COIN.value} or tag in {MessageTag.MVBA_ABA.value}:

        recv_queue = recv_queue[j]
    try:
        recv_queue.put_nowait((sender, msg))
    except AttributeError as e:
        # print((sender, msg))
        traceback.print_exc(e)

def mvba_msg_receiving_loop(recv_func, recv_queues):
    while True:
        handle_mvba_messages(recv_func, recv_queues)

logger = logging.getLogger(__name__)

def dumbo_mvba(sid, pid, N, f, PK, SK, PK1, SK1, input, decide, receive, send, predicate=lambda x: True, logger=None):
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
    :param input: ``input()`` is called to receive an input
    :param decide: ``decide()`` is eventually called
    :param receive: receive channel
    :param send: send channel
    :param predicate: ``predicate()`` represents the externally validated condition
    """
    assert PK.k == f+1
    assert PK.l == N
    assert PK1.k == N-f
    assert PK1.l == N

    pd = [None for n in range(N)]

    store = [0 for n in range(N)]
    lock = [0 for n in range(N)]
    done = [0 for n in range(N)]
    rc_ballot = [0 for n in range(N)]

    recv_finish_count = 0

    my_pd_input = Queue(1)
    aba_inputs = defaultdict(lambda: Queue(1))

    pd_recvs = [Queue() for _ in range(N)]
    coin_recv = Queue()
    pd_finish_recv = Queue()
    rc_recv = Queue()
    rc_pre_recv = Queue()
    aba_recvs = defaultdict(lambda: Queue())
    aba_coin_recvs = defaultdict(lambda: Queue())

    pd_outputs = [Queue() for _ in range(N)]
    aba_outputs = defaultdict(lambda: Queue(1))
    pd_leader_outputs = [Queue(1) for _ in range(N)]

    is_pd_delivered = [0] * N
    g_sid = sid

    recv_queues = MessageReceiverQueues(
        MVBA_COIN=coin_recv,
        MVBA_PD=pd_recvs,
        MVBA_PD_FINISH=pd_finish_recv,
        MVBA_RC=rc_recv,
        MVBA_RC_PREPARE=rc_pre_recv,
        MVBA_ABA=aba_recvs,
        MVBA_ABA_COIN=aba_coin_recvs
    )
    gevent.spawn(mvba_msg_receiving_loop, receive, recv_queues)

    """ 
        Setup the sub protocols Input Broadcast PDs"""
    v = input()
    #print("mvba input:", v)
    #my_pd_input.put(v)
    if predicate(v):
        my_pd_input.put(str(v))
    else:
        my_pd_input.put(str(""))
    for j in range(N):
        def make_pd_send(j): # this make will automatically deep copy the enclosed send func
            def pd_send(k, o):
                """PD send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                #print("node", pid, "is sending", o, "to node", k, "with the leader", j)
                send(k, ('MVBA_PD', j, o))
            return pd_send

        # Only leader gets input
        pd_input = my_pd_input.get if j == pid else None
        #
        pd[j] = gevent.spawn(provabledispersalbroadcast, sid + 'PD' + str(j), pid, N, f, PK1, SK1, j,
                           pd_input, pd_outputs[j].put_nowait, pd_recvs[j].get, make_pd_send(j))
        pd_leader_outputs[j] = pd[j].get

    wait_pd_signal = Event()
    wait_pd_signal.clear()

    def wait_for_pd_to_continue(leader):
        # Receive output from CBC broadcast for input values
        msg = pd_leader_outputs[leader]()
        # print("pd output: ",msg)
        if msg == 1:
            is_pd_delivered[leader] = 1
            # print(sum(is_pd_delivered))
            if sum(is_pd_delivered) == N:
                # print(111111)
                wait_pd_signal.set()
            # print("Leader %d finishes CBC for node %d" % (leader, pid))
            # print(is_cbc_delivered)
    pd_out_threads = [gevent.spawn(wait_for_pd_to_continue, node) for node in range(N)]
    wait_pd_signal.wait()

    for j in range(N):
        # print(len(pd_outputs[j]), ":")
        for _ in range(len(pd_outputs[j])):
            (mtype, context, sid_t, pid) = pd_outputs[j].get()
            #print("the out put: ", (mtype, context, sid, pid))
            if mtype == 'STORE':
                store[j] = context
            elif mtype == 'LOCK':
                lock[j] = (context[0], serialize(context[1]))
            elif mtype == 'DONE':
                done[j] = (context[0], serialize(context[1]))
                for i in range(N):
                    # print(pid, "brocast", (i, ('MVBA_PD_FINISH', 'quit', ('DONE', sid_t, done[j]))))
                    send(i, ('MVBA_PD_FINISH', 'quit', ('DONE', sid_t, done[j])))

    output_finish = -1
    def quitPD():
        # print("start to run quit")
        provens = 0
        RDY = set()
        RDYSenders = set()  # Peers that have sent us READY messages
        RDYSigShares = defaultdict(lambda: None)
        recdone = [0 for n in range(N)]
        recready = [0 for n in range(N)]
        revfinish = [0 for n in range(N)]
        sendfinish = 0


        def quitPD_send(k, o):
            # print("node", pid, "is sending", o, "to node", k)
            send(k, ('MVBA_PD_FINISH', 'quit', o))

        def broadcast(o):
            for i in range(N):
                quitPD_send(i, o)


        while True:
            sender, msg = pd_finish_recv.get()

            if msg[0] == 'DONE':
                # print("from sender:", sender, "to node:", pid)
                (_, sid_t, (roothash, raw_Sigma2)) = msg
                Sigma2 = deserialize1(raw_Sigma2)
                if recdone[sender] != 0:
                    print("not the first time receive done message from node ", sender)
                    continue
                recdone[sender] += 1
                try:
                    digest = PK1.hash_message(str(('LOCKED', sid_t, roothash)))
                    assert PK1.verify_signature(Sigma2, digest)
                except AssertionError:
                    print("Failed to validate DONE message:")
                    continue
                provens += 1
                if provens == N - f:
                    digest1 = PK.hash_message(str(('READY', g_sid)))
                    broadcast(('READY', g_sid, serialize(SK.sign(digest1))))

            if msg[0] == 'READY':
                (_, sid, raw_sigma) = msg

                sigma = deserialize1(raw_sigma)
                if recready[sender] != 0:
                    print("not the first time receive ready message from node ", sender)
                    continue
                recready[sender] += 1
                try:
                    digest = PK.hash_message(str(('READY', sid)))
                    assert PK.verify_share(sigma, sender, digest)
                except AssertionError:
                    print("Signature share failed in READY", (sid, pid, sender, msg))
                    continue
                RDY.add(sender)
                RDYSenders.add(sender)
                RDYSigShares[sender] = sigma
                if len(RDY) == f + 1:
                    sigmas1 = dict(list(RDYSigShares.items())[:f + 1])
                    # print(sigmas1)
                    Sigma_rdy = PK.combine_shares(sigmas1)
                    # print(Sigma1)
                    if sendfinish == 0:
                        broadcast(('FINISH', sid, serialize(Sigma_rdy)))
                        sendfinish += 1

            if msg[0] == 'FINISH':
                (_, sid, raw_Sigma_rdy) = msg
                Sigma_rdy = deserialize1(raw_Sigma_rdy)
                #print("from sender:", sender, "to node:", pid, sid)
                if revfinish[sender] != 0:
                    print("not the first time receive ready message from node ", sender)
                    continue
                revfinish[sender] += 1
                # recv_finish_count = recv_finish_count + 1

                try:
                    digest = PK.hash_message(str(('READY', sid)))
                    assert PK.verify_signature(Sigma_rdy, digest)
                except AssertionError:
                    print("???????READY Signature verify failed !", (sid, pid, sender, msg))

                    continue
                for j in range(N):
                    # print("pd", j, "in node", pid, "is killed")
                    pd[j].kill()

                if sendfinish == 0:
                    broadcast(('FINISH', sid, Sigma_rdy))
                    sendfinish += 1
                return sender

    pd_quit = gevent.spawn(quitPD)

    output_finish = pd_quit.get()
    wait_finish_signal = Event()
    wait_finish_signal.clear()
    def wait_for_finish_to_continue():
        # Receive output from CBC broadcast for input values
        if output_finish >= 0:
            wait_finish_signal.set()
            # print("Leader %d finishes CBC for node %d" % (leader, pid) )
            # print(is_cbc_delivered)

    finish_out_thread = gevent.spawn(wait_for_finish_to_continue)

    wait_finish_signal.wait()

    def coin_bcast(o):
        """Common coin multicast operation.
        :param o: Value to multicast.
        """
        for k in range(N):
            send(k, ('MVBA_COIN', 'election', o))

    permutation_coin = shared_coin(sid + 'COIN', pid, N, f,
                               PK, SK, coin_bcast, coin_recv.get, False)

    """
    Run a Coin instance to permute the nodes' IDs to sequentially elect the leaders
    """

    seed = permutation_coin('permutation')  # Block to get a random seed to permute the list of nodes
    # print(seed)
    np.random.seed(seed)
    pi = np.random.permutation(N)
    # print(pi)
    r = 0

    while True:
        #print(pi[r])
        l = pi[r]
        RCmsg = ('RCBALLOTPREPARE', sid + 'RCprepare', l, lock[l])
        for i in range(N):
            send(i, ('MVBA_RC_PREPARE', 'rc_pre', RCmsg))

        rc_pre_bottom = [0 for n in range(N)]
        output_rcpre = 0
        def RCprepare():
            while True:
                sender, msg = rc_pre_recv.get()
                if msg[0] == 'RCBALLOTPREPARE':
                    (_, PREsid , PREl, PRElock) = msg

                    if PRElock != 0:
                        (roothash, raw_Sigma1) = PRElock
                        Sigma1 = deserialize1(raw_Sigma1)
                        try:
                            digest = PK1.hash_message(str(('STORED', sid + 'PD' + str(l), roothash)))
                            assert PK1.verify_signature(Sigma1, digest)
                        except Exception as e:
                            print("????Failed to validate LOCK message:", e)
                            continue
                        lock[l] = PRElock
                        rc_ballot[l] = 1
                        return rc_ballot[l]
                    else:
                        rc_pre_bottom[sender] = 1
                        if sum(rc_pre_bottom) >= 2 * f + 1:
                            return 0

        rc_prepare = gevent.spawn(RCprepare)
        output_rcpre = rc_prepare.get()
        # print(output_rcpre)

        """
        ABA
        """

        def make_aba_send(rnd):  # this make will automatically deep copy the enclosed send func
            def aba_send(k, o):
                """CBC send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # print("node", pid, "is sending", o, "to node", k, "with the leader", j)
                send(k, ('MVBA_ABA', rnd, o))

            return aba_send

        def make_coin_bcast():
            def coin_bcast(o):
                """Common coin multicast operation.
                :param o: Value to multicast.
                """
                for k in range(N):
                    send(k, ('MVBA_ABA_COIN', r, o))

            return coin_bcast

        coin = shared_coin(sid + 'COIN' + str(r), pid, N, f,
                           PK, SK,
                           make_coin_bcast(), aba_coin_recvs[r].get)
        aba = gevent.spawn(binaryagreement, sid + 'ABA' + str(r), pid, N, f, coin,
                        aba_inputs[r].get, aba_outputs[r].put_nowait,
                       aba_recvs[r].get, make_aba_send(r))
        # aba.get is a blocking function to get aba output
        aba_inputs[r].put_nowait(output_rcpre)
        aba_r = aba_outputs[r].get()
        # print("aba_r:", aba_r)

        def make_rc_send():  # this make will automatically deep copy the enclosed send func
            def rc_send(k, o):
                """PD send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # print("node", pid, "is sending", o, "to node", k)
                send(k, ('MVBA_RC', 'RC-l', o))

            return rc_send
        if aba_r == 1:
            if aba_r == 1:
                rc = gevent.spawn(recastsubprotocol, pid, sid + 'PD' + str(l), N, f, PK1, SK1, rc_recv.get,
                                  make_rc_send(), store[l], lock[l])
                decide(eval(rc.get()))
            break
        r = r + 1
