import time
from queue import Queue

from gevent import monkey;

from honeybadgerbft.core.reliablebroadcast import encode, merkleTree, getMerkleBranch, merkleVerify

monkey.patch_all(thread=False)

from datetime import datetime
from collections import defaultdict
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
import hashlib, pickle


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def provablecbc(sid, pid, N, f, PK2s, SK2, leader, input, chunk, receive, send, logger=None):
    """Consistent broadcast
    :param str sid: session identifier
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
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

    # assert N >= 3*f + 1
    # assert f >= 0
    # assert 0 <= leader < N
    # assert 0 <= pid < N

    K = N - 2 * f
    EchoThreshold = N - f  # Wait for this many CBC_ECHO to send CBC_FINAL
    m = None
    fromLeader = None
    MyProof = None
    MyChunk = None
    finalSent = False
    cbc_echo_sshares = defaultdict(lambda: None)
    # print(sid, "PCBC starts...")
    def broadcast(o):
        #for i in range(N):
        #    send(i, o)
        send(-1, o)

    def decode_output(roothash):
        # Rebuild the merkle tree to guarantee decoding is correct
        if fromLeader == roothash:
            return MyChunk, MyProof, fromLeader
        else:
            return 0, 0, roothash

    if pid == leader:
        # The leader sends the input to each participant
        # print("block to wait for CBC input")

        m = input()  # block until an input is received

        # print("CBC input received: ", m)

        assert isinstance(m, (str, bytes, list, tuple))
        stripes = encode(K, N, m)
        mt = merkleTree(stripes)  # full binary tree
        roothash = mt[1]
        for i in range(N):
            branch = getMerkleBranch(i, mt)
            send(i, ('CBC_SEND', roothash, branch, stripes[i]))
        # print("Leader %d broadcasts CBC SEND messages" % leader)

    # Handle all consensus messages
    while True:
        # gevent.sleep(0)

        (j, msg) = receive()
        # if pid ==3 : print("recv3", (j, msg[0]))

        if msg[0] == 'CBC_SEND' and fromLeader is None:
            # CBC_SEND message
            (_, roothash, branch, stripe) = msg
            if j != leader:
                # print("Node %d receives a CBC_SEND message from node %d other than leader %d" % (pid, j, leader), msg)
                continue
            try:
                assert merkleVerify(N, stripe, roothash, branch, pid)
            except Exception as e:
                print("Failed to validate VAL message:", e)
                continue
            # Update
            fromLeader = roothash
            MyProof = branch
            MyChunk = stripe
            digest = hash((sid, roothash))
            chunk((MyChunk, MyProof, fromLeader))
            # if pid == 3: print("get chunk of", sid, "at ", time.time())
            send(leader, ('CBC_ECHO', ecdsa_sign(SK2, digest)))

        elif msg[0] == 'CBC_ECHO':
            # CBC_READY message
            # print("I receive CBC_ECHO from node %d" % j)
            if pid != leader:
                print("I reject CBC_ECHO from %d as I am not CBC leader:", j)
                continue
            (_, sig) = msg
            try:
                assert ecdsa_vrfy(PK2s[j], hash((sid, roothash)), sig)
            except AssertionError:
                print("1-Signature share failed in CBC!", (sid, pid, j, msg))
                continue
            # print("I accept CBC_ECHO from node %d" % j)
            cbc_echo_sshares[j] = sig
            if len(cbc_echo_sshares) >= EchoThreshold and not finalSent:
                sigmas = tuple(list(cbc_echo_sshares.items())[:N - f])
                # assert PK.verify_signature(Sigma, digestFromLeader)
                finalSent = True
                broadcast(('CBC_FINAL', roothash, sigmas))
                # print("Leader %d broadcasts CBC FINAL messages" % leader)

        elif msg[0] == 'CBC_FINAL':
            # CBC_FINAL message
            # print("I receive CBC_FINAL from node %d" % j)
            if j != leader:
                # print("Node %d receives a CBC_FINAL from node %d other than leader %d" % (pid, j, leader), msg)
                continue
            (_, r, sigmas) = msg
            try:
                assert len(sigmas) == N - f and len(set(sigmas)) == N - f
                digest = hash((sid, r))
                for (i, sig_i) in sigmas:
                    assert ecdsa_vrfy(PK2s[i], digest, sig_i)
            except AssertionError:
                print("Signature failed!", (sid, pid, j, msg))
                continue
            # print("CBC finished for leader", leader)
            output = decode_output(r)
            # if pid == 3: print("get output of", sid, "at ", time.time())
            return output, sigmas
