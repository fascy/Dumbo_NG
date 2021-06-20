import time

from gevent import monkey; monkey.patch_all(thread=False)

from datetime import datetime
from collections import defaultdict
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
import hashlib, pickle


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def provablebroadcast(sid, pid, N, f, PK2s, SK2, leader, input, value_output, recv, send, logger=None):
    """provablebroadcast
    :param str sid: session identifier
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
    :param int leader: ``0 <= leader < N``
    :param input: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param recv: :func:`receive()` blocks until a message is
        received; message is of the form::

            (i, (tag, ...)) = receive()

        where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m`` after receiving ``CBC-FINAL`` message
        from the leader

        .. important:: **Messages**

            ``PB_SEND( m )``
                sent from ``leader`` to each other party
            ``PB_ECHO( m, sigma )``
                sent to leader after receiving ``CBC-VAL`` message
            ``PB_PROOF( m, Sigma )``
                sent from ``leader`` after receiving :math:``N-f`` ``PB_ECHO`` messages
                where Sigma is computed over {sigma_i} in these ``PB_ECHO`` messages
    """

    #assert N >= 3*f + 1
    #assert f >= 0
    #assert 0 <= leader < N
    #assert 0 <= pid < N


    EchoThreshold = N - f      # Wait for this many PB_ECHO to send PB_PROOF
    digestFromLeader = None
    cbc_echo_sshares = defaultdict(lambda: None)
    m = None
    start = time.time()

    #print("CBC starts...")

    if pid == leader:
        # The leader sends the input to each participant
        #print("block to wait for CBC input")

        m = input() # block until an input is received

        #print("CBC input received: ", m)
        assert isinstance(m, (str, bytes, list, tuple))
        digestFromLeader = hash((sid, hash(m)))
        # print("leader", pid, "has digest:", digestFromLeader)
        cbc_echo_sshares[pid] = ecdsa_sign(SK2, digestFromLeader)
        value_output(m)
        send(-2, ('PB_SEND', m))
        #print("Leader %d broadcasts CBC SEND messages" % leader)


    # Handle all consensus messages
    while True:
        #gevent.sleep(0)

        (j, msg) = recv()
        #print("recv3", (j, msg))

        if msg[0] == 'PB_SEND' and digestFromLeader is None:
            # PB_SEND message
            (_, v) = msg
            if j != leader:
                print("Node %d receives a PB_SEND message from node %d other than leader %d" % (pid, j, leader), msg)
                continue
            digestFromLeader = hash((sid, hash(v)))
            #print("Node", pid, "has digest:", digestFromLeader, "for leader", leader, "session id", sid, "message", m)
            send(leader, ('PB_ECHO', ecdsa_sign(SK2, digestFromLeader)))
            if pid != leader:
                value_output(v)
                end = time.time()
                if logger != None:
                    logger.info("ABA %d completes in %f seconds" % (leader, end-start))

        elif msg[0] == 'PB_ECHO':
            # CBC_READY message
            #print("I receive PB_ECHO from node %d" % j)
            if pid != leader:
                print("I reject PB_ECHO from %d as I am not CBC leader:", j)
                continue
            (_, sig) = msg
            try:
                assert ecdsa_vrfy(PK2s[j], digestFromLeader, sig)
            except AssertionError:
                print("Signature share failed in CBC!", (sid, pid, j, msg))
                continue
            #print("I accept PB_ECHO from node %d" % j)
            cbc_echo_sshares[j] = sig
            if len(cbc_echo_sshares) >= EchoThreshold:
                sigmas = tuple(list(cbc_echo_sshares.items())[:N - f])
                end = time.time()
                if logger != None:
                    logger.info("ABA %d completes in %f seconds" % (leader, end-start))
                return sid, hash(m), sigmas
