from queue import Queue

from gevent import monkey;

monkey.patch_all(thread=False)

from datetime import datetime
from collections import defaultdict
import hashlib, pickle
from crypto.threshsig.boldyreva import serialize, deserialize1
from crypto.threshsig.boldyreva import TBLSPrivateKey, TBLSPublicKey

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()



def strongprovablebroadcast(sid, pid, N, f, PK1, SK1, leader, input, output, receive, send, logger=None, predicate=lambda x: True):
    """Consistent broadcast
    :param str sid: session identifier
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
    :param TBLSPublicKey PK1: ``boldyreva.TBLSPublicKey`` with threshold N-f
    :param TBLSPrivateKey SK1: ``boldyreva.TBLSPrivateKey`` with threshold N-f
    :param int leader: ``0 <= leader < N``
    :param input: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::

            (i, (tag, ...)) = receive()

        where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m`` after receiving ``CBC-FINAL`` message
        from the leader

        .. important:: **Messages**

            ``CBC_VAL( m )``
                sent from ``leader`` to each other party
            ``CBC_ECHO( m, sigma )``
                sent to leader after receiving ``CBC-VAL`` message
            ``CBC_FINAL( m, Sigma )``
                sent from ``leader`` after receiving :math:``N-f`` ``CBC_ECHO`` messages
                where Sigma is computed over {sigma_i} in these ``CBC_ECHO`` messages
    """

    assert N >= 3 * f + 1
    assert f >= 0
    assert 0 <= leader < N
    assert 0 <= pid < N

    EchoThreshold = N - f
    m = None
    digest1FromLeader = None
    digest2 = None
    echoSent = False
    finalSent = False
    cbc_echo_sshares = dict()
    cbc_echo_sshares2 = dict()
    def broadcast(o):
        for i in range(N):
            send(i, o)
        #send(-1, o)

    # print("SPBC starts...")

    if pid == leader:
        # The leader sends the input to each participant
        # print("block to wait for SPBC input")

        m = input()  # block until an input is received

        # print("SPBC input received: ", m[0])

        assert isinstance(m, (str, bytes, list, tuple))
        digest1FromLeader = PK1.hash_message(str((sid, m, "ECHO")))
        # print("leader", pid, "has digest:", digestFromLeader)
        cbc_echo_sshares[pid] = SK1.sign(digest1FromLeader)
        broadcast(('SPBC_SEND', m))
        # print("Leader %d broadcasts SPBC SEND messages" % leader)

    # Handle all consensus messages
    while True:
        # gevent.sleep(0)

        (j, msg) = receive()
        # print("recv", (j, msg))

        if msg[0] == 'SPBC_SEND':
            # CBC_SEND message
            (_, m) = msg
            if j != leader:
                if logger is not None: logger.info("A SPBC_SEND message from node %d other than leader %d" % (j, leader))
                print("A SPBC_SEND message from node %d other than leader %d" % (j, leader), msg)
                continue
            digest1FromLeader = PK1.hash_message(str((sid, m, "ECHO")))
            # print("Node", pid, "has message", m)
            send(leader, ('SPBC_ECHO', SK1.sign(digest1FromLeader)))

        elif msg[0] == 'SPBC_ECHO':
            # CBC_READY message
            # print("I receive CBC_ECHO from node %d" % j)
            if pid != leader:
                if logger is not None: logger.info(
                    "reject SPBC_ECHO from %d as %d is not the leader:" % (j, pid))
                print("reject SPBC_ECHO from %d as %d is not the leader:" % (j, pid))
                continue
            (_, sig1) = msg
            try:
                assert PK1.verify_share(sig1, j, digest1FromLeader)
            except AssertionError:
                print("Signature share failed in SPBC!", (sid, pid, j, msg))
                if logger is not None: logger.info("Signature share failed in SPBC!", (sid, pid, j, msg))
                continue
            # print("I accept CBC_ECHO from node %d" % j)
            cbc_echo_sshares[j] = sig1
            if len(cbc_echo_sshares) == EchoThreshold and not echoSent:
                sigmas = PK1.combine_shares(cbc_echo_sshares)
                # assert PK.verify_signature(Sigma, digestFromLeader)
                echoSent = True
                broadcast(('SPBC_READY', m, sigmas))
                # print("Leader %d broadcasts SPBC READY messages" % leader)

        elif msg[0] == 'SPBC_READY':
            # SPBC_READY message
            if j != leader:
                if logger is not None: logger.info(
                    "A SPBC_SEND message from node %d other than leader %d" % (j, leader))
                print("A SPBC_SEND message from node %d other than leader %d" % (j, leader), msg)
                continue
            (_, m, sigmas) = msg
            try:
                assert PK1.verify_signature(sigmas, PK1.hash_message(str((sid, m, "ECHO"))))
            except AssertionError:
                if logger is not None: logger.info("Signature failed!", (sid, pid, j, msg))
                print("Signature failed!", (sid, pid, j, msg))
                continue
            # print("CBC finished for leader", leader)
            digest2 = PK1.hash_message(str((sid, m, "FINAL")))
            send(leader, ('SPBC_FINAL', SK1.sign(digest2)))
            if output is not None:
                output((sid, pid, m, sigmas))

        elif msg[0] == 'SPBC_FINAL':
            # CBC_READY message
            # print("I receive CBC_ECHO from node %d" % j)
            if pid != leader:
                if logger is not None: logger.info(
                    "reject SPBC_FINAL from %d as %d is not the leader:" % (j, pid))
                print("reject SPBC_FINAL from %d as %d is not the leader:" % (j, pid))
                continue
            (_, sig2) = msg
            digest2 = PK1.hash_message(str((sid, m, "FINAL")))
            try:
                assert PK1.verify_share(sig2, j, digest2)
            except AssertionError:
                print("Signature share failed in SPBC!", (sid, pid, j, msg))
                if logger is not None: logger.info("Signature share failed in SPBC!", (sid, pid, j, msg))
                continue
            # print("I accept CBC_ECHO from node %d" % j)
            cbc_echo_sshares2[j] = sig2
            if len(cbc_echo_sshares2) == EchoThreshold and not finalSent:
                # print("---------------------")
                sigmas2 = PK1.combine_shares(cbc_echo_sshares2)
                # assert PK.verify_signature(Sigma, digestFromLeader)
                finalSent = True
                broadcast(('SPBC_DONE', m, sigmas2))
                # print("Leader %d broadcasts SPBC DONE messages" % leader)

        elif msg[0] == 'SPBC_DONE':
            # SPBC_DONE message
            if j != leader:
                if logger is not None: logger.info(
                    "A SPBC_SEND message from node %d other than leader %d" % (j, leader))
                print("A SPBC_SEND message from node %d other than leader %d" % (j, leader), msg)
                continue
            (_, m, sigmas2) = msg
            try:
                assert PK1.verify_signature(sigmas2, PK1.hash_message(str((sid, m, "FINAL"))))
            except AssertionError:
                if logger is not None: logger.info("Signature failed!", (sid, pid, j, msg))
                print("Signature failed!", (sid, pid, j, msg))
                continue
            return m, sigmas2
