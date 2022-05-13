import traceback
import gevent

from collections import namedtuple
from gevent import Greenlet
from gevent.event import Event
from enum import Enum
from collections import defaultdict
from gevent.queue import Queue
from dumbomvbastar.core.provabledispersal import provabledispersalbroadcast
from dumbomvbastar.core.recast import recastsubprotocol
from honeybadgerbft.exceptions import UnknownTagError
from speedmvba.core.smvba_e_cp import speedmvba


class MessageTag(Enum):
    MVBA_PD = 'MVBA_PD'  # [Queue()] * N
    MVBA_RC = 'MVBA_RC'
    MVBA_UNDER = 'MVBA_UNDER'


MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('MVBA_PD', 'MVBA_RC', 'MVBA_UNDER'))


def recv_loop(recv_func, recv_queues):
    while True:
        gevent.sleep(0)
        sender, (tag, j, msg) = recv_func()
        if tag not in MessageTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, MessageTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]
        # if tag == MessageTag.MVBA_PD.value or tag == MessageTag.MVBA_RC:
        recv_queue = recv_queue[j]
        try:
            recv_queue.put_nowait((sender, msg))
            # print(tag, sender, j, msg[0])
        except AttributeError as e:
            traceback.print_exc(e)


def smvbastar(sid, pid, N, f, PK, SK, PK2s, SK2, input, decide, receive, send, predicate=lambda x: True,
              logger=None):
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
    assert PK.k == f + 1
    assert PK.l == N

    pd = [None for n in range(N)]

    store = [Queue(1) for _ in range(N)]
    lock = [Queue(1) for _ in range(N)]
    my_lock = 0
    my_pd_input = Queue(1)

    pd_recvs = [Queue() for _ in range(N)]
    rc_recv = defaultdict(lambda: Queue())
    under_recv = defaultdict(lambda: Queue())

    pd_outputs = [Queue() for _ in range(N)]
    pd_leader_outputs = [Queue(1) for _ in range(N)]

    recv_queues = MessageReceiverQueues(
        MVBA_PD=pd_recvs,
        MVBA_RC=rc_recv,
        MVBA_UNDER=under_recv
    )

    recv_thread = gevent.spawn(recv_loop, receive, recv_queues)

    v = input()
    my_pd_input.put(str(v))

    # start n PD instances
    for j in range(N):
        def make_pd_send(j):  # this make will automatically deep copy the enclosed send func
            def pd_send(k, o):
                """PD send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # print("node", pid, "is sending", o, "to node", k, "with the leader", j)
                send(k, ('MVBA_PD', j, o))

            return pd_send

        # Only leader gets input
        pd_input = my_pd_input.get if j == pid and predicate(v) else None
        #
        pd[j] = gevent.spawn(provabledispersalbroadcast, sid + 'PD' + str(j), pid, N, f, PK2s, SK2, j,
                             pd_input, pd_outputs[j].put_nowait, pd_recvs[j].get, make_pd_send(j))
        # pd_leader_outputs[j] = pd[j].get

    pd_count = [0 for _ in range(N)]

    def output_receve():
        def o_recv(j):
            def _recv():
                (mtype, context, sid_t, pid) = pd_outputs[j].get()
                # print 'RECV %8s [%2d -> %2d]' % (o[0], i, j)
                return (mtype, context, sid_t, pid)

            return _recv

        return [o_recv(j) for j in range(N)]

    recv_pds = output_receve()

    wait_lock_signal = Event()
    wait_lock_signal.clear()

    def get_PD_output(recv_func, j):
        nonlocal my_lock
        while pd_count[j] < 2:
            gevent.sleep(0)
            (mtype, context, sid_t, pid) = recv_func()
            # print("the out put: ", (mtype, sid, pid))
            if mtype == 'STORE':
                store[j].put_nowait(context)
                pd_count[j] += 1
            elif mtype == 'LOCK':
                if lock[j].qsize() == 0:
                    lock[j].put_nowait((context[0], context[1]))
                    pd_count[j] += 1
                if j == pid:
                    my_lock = (context[0], context[1])
                    wait_lock_signal.set()

    for j in range(N):
        gevent.spawn(get_PD_output, recv_pds[j], j)
    wait_lock_signal.wait()
    r = 0

    while True:
        def make_under_send(r):  # this make will automatically deep copy the enclosed send func
            def under_send(k, o):
                """MVBA under send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                send(k, ('MVBA_UNDER', r, o))
                # print("node", pid, "is sending", o, "to node", k, "in round ", r)

            return under_send

        def make_rc_send(r):  # this make will automatically deep copy the enclosed send func
            def rc_send(k, o):
                """PD send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # print("node", pid, "is sending", o, "to node", k)
                send(k, ('MVBA_RC', r, o))

            return rc_send

        # invoke mvba as a black box
        vaba_input = Queue(1)
        vaba_output = Queue(1)

        vaba_input.put_nowait((pid, my_lock))

        def make_under_predicate():
            def vaba_predicate(vj):
                return True

            return vaba_predicate

        under_thread_r = Greenlet(speedmvba, sid + 'MVBA-UNDER', pid, N, f, PK, SK, PK2s, SK2,
                                  vaba_input.get, vaba_output.put_nowait,
                                  under_recv[r].get, make_under_send(r), predicate=make_under_predicate(),
                                  logger=None)
        under_thread_r.start()
        out = vaba_output.get()
        (l, lock_l) = out
        if lock[l].qsize() == 0:
            lock[l].put_nowait(lock_l)
        # print(pid, "start rc in ", sid)
        rc = gevent.spawn(recastsubprotocol, pid, sid + 'PD' + str(l), N, f, PK2s, SK2, rc_recv[r].get,
                          make_rc_send(r), store[l].get, lock[l].get)
        rc_out = rc.get()
        # print(pid, "returns in ", sid)
        # print(tuple(eval(rc_out)))
        if predicate(tuple(eval(rc_out))):
            decide(tuple(eval(rc_out)))
            break
        else:
            r = r + 1

    recv_thread.join()
