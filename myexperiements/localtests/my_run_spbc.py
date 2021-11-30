import random

import gevent
from gevent import Greenlet
from gevent.queue import Queue

from speedmbva.core.spbc import strongprovablebroadcast
from crypto.threshsig.boldyreva import dealer


# CBC
def simple_router(N, maxdelay=0.01, seed=None):
    """Builds a set of connected channels, with random delay
    @return (receives, sends)
    """
    rnd = random.Random(seed)
    #if seed is not None: print 'ROUTER SEED: %f' % (seed,)

    queues = [Queue() for _ in range(N)]

    def makeSend(i):
        def _send(j, o):
            delay = rnd.random() * maxdelay
            #print 'SEND %8s [%2d -> %2d] %.2f' % (o[0], i, j, delay)
            gevent.spawn_later(delay, queues[j].put, (i,o))
            #queues[j].put((i, o))
        return _send

    def makeRecv(j):
        def _recv():
            (i,o) = queues[j].get()
            #print 'RECV %8s [%2d -> %2d]' % (o[0], i, j)
            return (i,o)
        return _recv

    return ([makeSend(i) for i in range(N)],
            [makeRecv(j) for j in range(N)])


def _test_cbc(N=4, f=1, leader=None, seed=None):
    # Test everything when runs are OK
    sid = 'sidA'
    # Generate threshold sig keys
    sPK, sSKs = dealer(N, N-f, seed=seed)

    rnd = random.Random(seed)
    router_seed = rnd.random()
    if leader is None: leader = rnd.randint(0, N-1)
    print("The leader is: ", leader)
    sends, recvs = simple_router(N, seed=seed)

    threads = []
    leader_input = Queue(1)
    output_list = Queue()
    for i in range(N):
        input = leader_input.get if i == leader else None
        t = Greenlet(strongprovablebroadcast, sid, i, N, f, sPK, sSKs[i], leader, input,output_list.put_nowait, recvs[i], sends[i])
        t.start()
        threads.append(t)

    m = "Hello! This is a test message."
    leader_input.put(m)
    gevent.joinall(threads)
    for t in threads:
        print(t.value)
        while output_list.qsize() > 0:
            print("---", output_list.get())
    # Assert the CBC-delivered values are same to the input

    assert [t.value[0] for t in threads] == [m]*N
    # Assert the CBC-delivered authentications (i.e., signature) are valid
    digest = sPK.hash_message(str((sid, m, "FINAL")))
    assert [sPK.verify_signature(t.value[1], digest) for t in threads] == [True]*N


def test_cbc(N, f, seed):
    _test_cbc(N=N, f=f, seed=seed)


if __name__ == '__main__':
    test_cbc(4, 1, None)
