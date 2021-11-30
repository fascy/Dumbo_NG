from queue import Queue

from gevent import monkey;

from honeybadgerbft.core.reliablebroadcast import encode, merkleTree, getMerkleBranch, merkleVerify, decode

monkey.patch_all(thread=False)

from datetime import datetime
from collections import defaultdict
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
import hashlib, pickle


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def retrival(pid, sid, N, f, PK1, SK1, client, receive, send, store, logger=None):

    def broadcast(o):
        for i in range(N):
            send(i, o)
        # send(-1, o)

    assert N >= 3 * f + 1
    assert f >= 0
    assert 0 <= pid < N
    K = N - 2 * f
    count = 0
    (chunk, proof, root) = store
    stripes = [None for _ in range(N)]

    if pid == client:
        # print("CBC input received: ", m[0])
        broadcast(('Request', sid, root))

    if chunk == 0 and pid != client:
        print("did not store the value in ", sid)
        return 0

    while True:
        (j, msg) = receive()
        if msg[0] == 'Request':
            (_, r_sid, r_root) = msg
            if j != client:
                # print("Node %d receives a CBC_SEND message from node %d other than leader %d" % (pid, j, leader), msg)
                continue
            if r_sid != sid:
                print(r_sid, "is not this sid:", sid)
                continue
            send(client, ('Return', chunk, proof, root))
            if pid != client:
                return 1
        if msg[0] == 'Return':
            if pid != client:
                print(pid, "is not the client")
                continue

            (_, chunk, proof, r_root) = msg
            try:
                assert merkleVerify(N, chunk, r_root, proof, j)
            except Exception as e:
                print("Failed to validate VAL message:", e)
                continue

            stripes[j] = chunk
            count += 1
            if count == K:
                m = decode(K, N, stripes)
                # print(m)
                return m