# new rc
import hashlib
import pickle
import time
from collections import defaultdict

import gevent
from gevent import monkey
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from dumbobft.core.provablereliablebroadcast import encode, decode
from honeybadgerbft.core.reliablebroadcast import merkleTree, getMerkleBranch, merkleVerify


def recastsubprotocol(pid, sid, N, f,  PK2s, SK2, receive, send, getstore, getlock):

    assert N >= 3 * f + 1
    assert f >= 0
    assert 0 <= pid < N
    K = f + 1

    rclocksend = False
    rcstorerec = [0 for n in range(N)]
    commit = defaultdict(lambda: [None for _ in range(N)])
    # commit = defaultdict(set)

    def hash(x):
        return hashlib.sha256(pickle.dumps(x)).digest()

    def broadcast(o):
        send(-1, o)

    def getinput():
        nonlocal rclocksend

        getinputcount = 0
        while getinputcount < 2:
            gevent.sleep(0)
            try:
                lock = getlock()
                # print(pid, "get lock")
                if not rclocksend:
                    broadcast(('RCLOCK', sid, lock))
                    rclocksend = True
                    getinputcount += 1
            except:
                pass
            try:
                store = getstore()
                # print(pid, "get store")
                broadcast(('RCSTORE', sid, store))
                getinputcount += 1
            except:
                pass
    gevent.spawn(getinput)

    while True:
        gevent.sleep(0)
        sender, msg = receive()
        # print(sid, pid, ": receive", msg[0])
        if msg[0] == 'RCLOCK':
            (_, sid, lock) = msg
            (roothash, raw_Sigma1) = lock
            # print(lock)
            try:
                digest = hash(str(('STORED', sid, roothash)))
                try:
                    for (k, sig) in raw_Sigma1:
                        assert ecdsa_vrfy(PK2s[k], digest, sig)
                except AssertionError as e:
                    print("Signature failed!", e)
                    continue
                # assert PK1.verify_signature(deserialize1(raw_Sigma1), digest)
            except Exception as e:
                print("Failed to validate LOCK message:", e)
                continue
            if not rclocksend:
                broadcast(('RCLOCK', sid, lock))
                rclocksend = True
            if sum(x is not None for x in commit[roothash]) >= f + 1:
                # print(pid, sid, "f+1")
                start = time.time()
                v = decode(K, N, commit[roothash])
                if merkleTree(encode(K, N, v))[1] == roothash:
                    # print("now print v:", bytes.decode(v))
                    end = time.time()
                    # print(pid, "return rc", sid)
                    return bytes.decode(v)
                else:
                    return 0

        if msg[0] == 'RCSTORE':
            (_, sid, store) = msg
            (roothash, sender, stripe, branch) = store
            if rcstorerec[sender] != 0:
                print("not the first time receive rcstore from node ", sender)
                continue
            try:
                assert merkleVerify(N, stripe, roothash, branch, sender)
            except Exception as e:
                print("Failed to validate STORE message:", e)
                continue
            rcstorerec[sender] += 1

            # print(stripe)
            commit[roothash][sender] = stripe

            if rclocksend and sum(x is not None for x in commit[roothash]) == f+1:
                # print(pid, ": has f+1 stripes")

                v = decode(K, N, commit[roothash])
                if merkleTree(encode(K, N, v))[1] == roothash:
                    # print("now print v:", bytes.decode(v))

                    # print(pid, "return rc", sid)
                    return bytes.decode(v)
                else:
                    return 0