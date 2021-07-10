import time
from collections import defaultdict
from gevent import monkey
from crypto.threshsig.boldyreva import serialize, deserialize1
from dumbobft.core.provablereliablebroadcast import encode, decode
from honeybadgerbft.core.reliablebroadcast import merkleTree, getMerkleBranch, merkleVerify


def recastsubprotocol(pid, sid, N, f, PK1, SK1, receive, send, store, lock):

    def broadcast(o):
        send(-1, o)

    assert N >= 3 * f + 1
    assert f >= 0
    assert 0 <= pid < N
    K = f + 1

    rclocksend = False
    rcstorerec = [0 for n in range(N)]
    commit = defaultdict(lambda: [None for _ in range(N)])
    # commit = defaultdict(set)
    if lock != ():
        broadcast(('RCLOCK', sid, lock))
    if store != ():
        broadcast(('RCSTORE', sid, store))

    while True:
        sender, msg = receive()
        if msg[0] == 'RCLOCK':
            (_, sid, lock) = msg
            (roothash, raw_Sigma1) = lock
            try:
                digest = PK1.hash_message(str(('STORED', sid, roothash)))
                assert PK1.verify_signature(deserialize1(raw_Sigma1), digest)
            except Exception as e:
                print("Failed to validate LOCK message:", e)
                continue
            if not rclocksend:
                broadcast(('RCLOCK', sid, lock))
                rclocksend = True
            if sum(x is not None for x in commit[roothash]) >= f + 1:
                start = time.time()
                v = decode(K, N, commit[roothash])
                if merkleTree(encode(K, N, v))[1] == roothash:
                    # print("now print v:", v)
                    end = time.time()
                    #print("decode time:" + str(end - start))
                    return v
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
            # print(pid, ":", commit[roothash])


