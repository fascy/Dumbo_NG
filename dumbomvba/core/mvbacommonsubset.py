import json
import traceback
import gevent
from collections import namedtuple
from enum import Enum
from gevent import monkey
from dumbomvba.core.dumbomvba import dumbo_mvba
from gevent.queue import Queue
from honeybadgerbft.exceptions import UnknownTagError
from crypto.threshsig.boldyreva import serialize, deserialize1



class MessageTag(Enum):
    ACS_DIFFUSE = 'ACS_DIFFUSE'            # Queue()
    ACS_MVBA = 'ACS_MVBA'


MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('ACS_DIFFUSE', 'ACS_MVBA'))


def handle_vacs_messages(recv_func, recv_queues):
    sender, (tag, msg) = recv_func()
    # print(sender, (tag, msg))
    if tag not in MessageTag.__members__:
        # TODO Post python 3 port: Add exception chaining.
        # See https://www.python.org/dev/peps/pep-3134/
        raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
            tag, MessageTag.__members__.keys()))
    recv_queue = recv_queues._asdict()[tag]
    try:
        recv_queue.put_nowait((sender, msg))
    except AttributeError as e:
        # print((sender, msg))
        traceback.print_exc(e)


def vacs_msg_receiving_loop(recv_func, recv_queues):
    while True:
        handle_vacs_messages(recv_func, recv_queues)


def mvbacommonsubset(sid, pid, N, f, PK, SK, PK1, SK1, input, decide, receive, send, predicate=lambda i, v: True):
    """Validated vector consensus. It takes an input ``vi`` and will
    finally writes the decided value (i.e., a vector of different nodes' vi) into ``decide`` channel.
    Each vi is validated by a predicate function predicate(i, vi)

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
    :param predicate: ``predicate(i, v)`` represents the externally validated condition where i represent proposer's pid
    """

    assert PK.k == f + 1
    assert PK.l == N
    assert PK1.k == N - f
    assert PK1.l == N

    """ 
    """
    """ 
    Some instantiations
    """
    """ 
    """

    valueSenders = set()  # Peers that have sent us valid VAL messages

    mvba_input = Queue(1)
    mvba_recv = Queue()
    mvba_output = Queue(1)

    diffuse_recv = Queue()

    recv_queues = MessageReceiverQueues(
        ACS_DIFFUSE=diffuse_recv,
        ACS_MVBA=mvba_recv
    )
    gevent.spawn(vacs_msg_receiving_loop, receive, recv_queues)

    def make_mvba_send():  # this make will automatically deep copy the enclosed send func
        def mvba_send(k, o):
            """VACS-VABA send operation.
            :param k: Node to send.
            :param o: Value to send.
            """
            send(k, ('ACS_MVBA', o))

        return mvba_send

    def make_mvba_predicate():
        def mvba_predicate(m):
            counter = 0
            if type(m) is tuple:
                if len(m) == N:
                    for i in range(N):
                        (j, vj, sig) = m[i]
                        digest = PK1.hash_message(str(vj))
                        if m[i] is not None and predicate(i, m[i]) and PK1.verify_share(sig, j, digest):
                            counter += 1
            return True if counter >= N - f else False

        return mvba_predicate
    mvba = gevent.spawn(dumbo_mvba, sid + 'MVBA', pid, N, f, PK, SK, PK1, SK1,
                        mvba_input.get, mvba_output.put_nowait, mvba_recv.get, make_mvba_send(), make_mvba_predicate())

    """ 
    """
    """ 
    Execution
    """
    """ 
    """
    v = input()
    #print(pid, v)
    assert predicate(pid, v)

    for k in range(N):
        digest = PK1.hash_message(str((sid, v)))
        send(k, ('ACS_DIFFUSE', (sid, v, serialize(SK1.sign(digest)))))

    values = [None] * N
    while True:
        sender, msg = diffuse_recv.get()
        (sid, vj, raw_sig) = msg
        sig = deserialize1(raw_sig)
        try:
            digest = PK1.hash_message(str((sid, vj)))
            assert PK1.verify_share(sig, sender, digest)
        except AssertionError:
            print("Signature verify failed in diffuse!", (sid, pid, sender, msg))
            continue
        valueSenders.add(sender)
        values[sender] = vj
        if len(valueSenders) >= N - f:
            break
    import pickle
    val_str = pickle.dumps(values)
    mvba_input.put(val_str)
    out = mvba_output.get()
    out_obj = pickle.loads(out)
    decide(out_obj)
    mvba.kill()
