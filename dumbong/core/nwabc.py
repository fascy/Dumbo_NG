from gevent import monkey;

from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign

monkey.patch_all(thread=False)
import hashlib, pickle
from collections import defaultdict
import time

import gevent
from gevent.queue import Queue

stop = 0


def nwatomicbroadcast(sid, pid, N, f, Bsize, PK2s, SK2, leader, input, output, receive, send, logger=None, pro=1):
    """nw-abc

    :param sid: session id
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param PK1: ``boldyreva.TBLSPublicKey`` with threshold n-f
    :param SK1: ``boldyreva.TBLSPrivateKey`` with threshold n-f
    :param int leader: ``0 <= leader < N``
    :param input: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::

            (i, (tag, ...)) = receive()

        where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m`` after receiving :math:`2f+1` ``READY`` messages
        and :math:`N-2f` ``ECHO`` messages

        .. important:: **Messages**
            ``PROPOSAL( sid, s, tx[s], sigma[s-1])``
                snet from ``leader`` to all parties
            ``VOTE( sid, s, sig[s])``
                sent after receiving ``PROPOSAL`` message

    """
    assert N >= 3 * f + 1
    assert f >= 0
    assert 0 <= leader < N
    assert 0 <= pid < N
    SignThreshold = 2 * f + 1  # Wait for this many READY to output
    s = 1
    BATCH_SIZE = Bsize
    proposals = defaultdict()
    Txs = defaultdict(lambda: Queue())
    Sigmas = defaultdict(lambda: Queue(1))
    sts = defaultdict(lambda: Queue(1))
    voters = defaultdict(lambda: set())
    votes = defaultdict(lambda: dict())
    catchup = 0
    stop = 0

    s_time = 0
    e_time = 0
    tps = 0

    def hash(x):
        return hashlib.sha256(pickle.dumps(x)).digest()

    def broadcast(o):
        send(-1, o)

    if pid == leader:
        # print()
        # proposals[1] = [input() for _ in range(BATCH_SIZE)]
        proposals[1] = input()
        broadcast(('PROPOSAL', sid, s, proposals[1], time.time(), 0))
    stop = 0

    s_time = time.time()

    def handel_messages():
        nonlocal catchup, s
        # print("start to handel msg")
        while True:
            sender, msg = receive(timeout=1000)
            # print(msg[0])
            assert sender in range(N)
            delta = 0
            if stop != 0:
                # if logger is not None: logger.info("this nw-abc is stopped")
                return 0

            if msg[0] == 'PROPOSAL':
                nonlocal sid
                (_, sid_r, r, tx, st, sigma) = msg
                if sender != leader:
                    if logger is not None: logger.info("PROPOSAL message from other than leader: %d" % sender)
                    continue
                assert sid_r == sid
                if r > s:
                    delta = 1
                    catchup += 1
                if s % 100 == 0 or delta == 1:
                    print("sid: %s, %d catch up in total" % (sid, catchup))
                    if logger is not None: logger.info("sid: %s, %d catch up in total" % (sid, catchup))
                if r == 1:
                    Txs[r].put_nowait(tx)
                    sts[r].put_nowait(st)
                elif r > 1:
                    Txs[r].put_nowait(tx)
                    Sigmas[r - 1].put_nowait(sigma)
                    sts[r].put_nowait(st)

            if msg[0] == 'VOTE' and pid == leader:
                (_, sid, r, sigsh) = msg
                if r < s - 5:
                    continue
                if len(voters[r]) >= N - f:
                    continue

                if sender not in voters[r]:
                    try:
                        digest1 = hash(str(proposals[r])) + hash(str((sid, r)))
                        assert ecdsa_vrfy(PK2s[sender], digest1, sigsh)
                        # assert ecdsa.verify(sigsh, digest1, PK2s[sender], curve=curve.P192)
                        # print(sender, PK2s[sender])
                    except AssertionError:
                        if logger is not None: logger.info("Signature share failed in vote for %s!" % str(msg))
                        continue
                    voters[r].add(sender)
                    votes[r][sender] = sigsh
                    if len(voters[r]) == N - f:
                        Sigma1 = tuple(votes[r].items())
                        try:
                            # proposals[r + 1] = [input() for _ in range(BATCH_SIZE)]
                            proposals[r + 1] = input()
                        except  Exception as e:
                            # if logger is not None: logger.info("all msg in buffer has been sent!")
                            proposals[r + 1] = 0

                            broadcast(('PROPOSAL', sid, r + 1, proposals[r + 1], time.time(), Sigma1))
                        broadcast(('PROPOSAL', sid, r + 1, proposals[r + 1], time.time(), Sigma1))

            gevent.sleep(0)

    def decide_output():
        nonlocal sid, s, stop
        last_tx = 0
        while True:
            if s > 1:
                try:
                    last_sigs = Sigmas[s - 1].get()
                    last_st = sts[s - 1].get()
                    del Sigmas[s - 1]
                    del sts[s - 1]
                except Exception as e:
                    if logger is not None: logger.info("fail to get sigmas of tx in round %d" % s - 1)
                    continue

                try:
                    assert len(last_sigs) >= N - f
                except AssertionError:
                    if logger is not None: logger.info("No enough ecdsa signatures!")
                    continue

                try:
                    # digest2 = hash(str((sid, s - 1, last_tx)))
                    digest2 = hash(str(last_tx)) + hash(str((sid, s - 1)))
                    for item in last_sigs:
                        (sender, sig_p) = item
                        assert ecdsa_vrfy(PK2s[sender], digest2, sig_p)
                        # assert ecdsa.verify(sig_p, digest2, PK2s[sender], curve=curve.P192)
                except AssertionError:
                    if logger is not None: logger.info("ecdsa signature failed!")
                    continue
                if output is not None:
                    output((sid, s - 1, hash(str(last_tx)), last_sigs, last_st))
                    # if logger is not None: logger.info("%s %d: %f" % (sid, s-1, time.time()-last_st))
                    if pid == leader:
                        if s > 20:
                            del proposals[s - 20]
                            del votes[s - 20]
                            del voters[s - 20]
                    gevent.sleep(0)
            try:
                tx_s = Txs[s].get()
                del Txs[s]
            except  Exception as e:
                if logger is not None: logger.info("Failed to get tx!")
                continue

            try:
                assert tx_s != 0
            except AssertionError:
                stop = 1
                return 0
            digest1 = hash(str(tx_s)) + hash(str((sid, s)))
            # sig = ecdsa.sign(digest1, SK2, curve=curve.P192)
            sig = ecdsa_sign(SK2, digest1)
            send(leader, ('VOTE', sid, s, sig))
            s = s + 1
            last_tx = tx_s

        gevent.sleep(0)

    recv_thread = gevent.spawn(handel_messages)
    gevent.sleep(0)
    outpt_thread = gevent.spawn(decide_output)
    gevent.joinall([recv_thread, outpt_thread])
    e_time = time.time()

    tps = Bsize * (s - 1) / (e_time - s_time)
    # if logger is not None: logger.info(
    #     "node: %d sid: %s tps: %d running time: %f" % (pid, str(sid) + " " + str(s - 1), tps, (e_time - s_time)))
