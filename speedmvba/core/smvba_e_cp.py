from gevent import monkey;

from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from speedmvba.core.spbc_ec_cp import strongprovablebroadcast

monkey.patch_all(thread=False)
import hashlib
import pickle
import time

import gevent
from collections import namedtuple
from gevent import Greenlet
from gevent.event import Event
from enum import Enum
from collections import defaultdict
from gevent.queue import Queue



from honeybadgerbft.exceptions import UnknownTagError


class MessageTag(Enum):
    MVBA_SPBC = 'MVBA_SPBC'  # [Queue()] * N
    MVBA_ELECT = 'MVBA_ELECT'  #
    MVBA_ABA = 'MVBA_ABA'  # [Queue()] * Number_of_ABA_Iterations
    MVBA_HALT = 'MVBA_HALT'


MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('MVBA_SPBC', 'MVBA_ELECT', 'MVBA_ABA', 'MVBA_HALT'))


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def speedmvba(sid, pid, N, f, PK, SK, PK2s, SK2, input, decide, receive, send, predicate=lambda x: True, logger=None):
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
    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
    :param input: ``input()`` is called to receive an input
    :param decide: ``decide()`` is eventually called
    :param receive: receive channel
    :param send: send channel
    :param predicate: ``predicate()`` represents the externally validated condition
    """

    # print("Starts to run validated agreement...")

    assert PK.k == f + 1
    assert PK.l == N

    """ 
    """
    """ 
    Some instantiations
    """
    """ 
    """

    r = 0
    h = 0
    hasOutputed = False

    def recv_loop(recv_func, recv_queues):
        nonlocal r
        while h == 0:
            gevent.sleep(0.0001)
            try:
                sender, (tag, r0, j, msg) = recv_func()
            except:
                continue
            if r0 < r - 1:
                continue
            # print("recv2", (sender, (tag, j, msg[0])))
            if tag not in MessageTag.__members__:
                raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                    tag, MessageTag.__members__.keys()))
            recv_queue = recv_queues._asdict()[tag]
            if tag in {MessageTag.MVBA_SPBC.value}:
                try:
                    recv_queue = recv_queue[r0][j]
                except:
                    pass
            elif tag not in {MessageTag.MVBA_ELECT.value, MessageTag.MVBA_HALT.value}:
                recv_queue = recv_queue[r0]
            try:
                recv_queue.put_nowait((sender, msg))
            except AttributeError as e:
                # print((sender, msg))
                # traceback.print_exc(e)
                pass

    my_spbc_input = Queue(1)

    aba_recvs = defaultdict(lambda: Queue())

    spbc_recvs = defaultdict(lambda: [Queue() for _ in range(N)])
    coin_recv = Queue()
    # commit_recvs = [Queue() for _ in range(N)]
    halt_recv = Queue()

    spbc_threads = {}
    spbc_s1_threads = {}
    spbc_outputs = {}
    spbc_s1_list = {}
    spbc_flags = {}
    s1_list = {}

    is_spbc_delivered = {}
    is_s1_delivered = {}

    Leaders = {}

    recv_queues = MessageReceiverQueues(
        MVBA_SPBC=spbc_recvs,
        MVBA_ELECT=coin_recv,
        MVBA_ABA=aba_recvs,
        MVBA_HALT=halt_recv

    )
    recv_loop_thred = Greenlet(recv_loop, receive, recv_queues)
    recv_loop_thred.start()

    def broadcast(o):
        send(-1, o)

    def spbc_predicate(m):
        msg, proof, round, tag = m

        # both yes and no vote
        if round == 0:
            return 3
        L = Leaders[round]
        if tag == 'yn':
            hash_e = hash(str((sid + 'SPBC' + str(L), msg, "ECHO")))
            try:
                for (k, sig_k) in proof:
                    assert ecdsa_vrfy(PK2s[k], hash_e, sig_k)
                    # assert ecdsa.verify(sig_k, hash_e, PK2s[k], curve=curve.P192)
            except AssertionError:
                if logger is not None: logger.info("sig L verify failed!")
                print("sig L verify failed!")
                return -1

            return 1
        if tag == 'no':
            digest_no_no = hash(str((sid, L, r - 1, 'vote')))
            try:
                for (k, sig_nono) in proof:
                    assert ecdsa_vrfy(PK2s[sender], digest_no_no, sig_nono)
                    # assert ecdsa.verify(sig_nono, digest_no_no, PK2s[sender], curve=curve.P192)
            except AssertionError:
                if logger is not None: logger.info("sig nono verify failed!")
                print("sig nono verify failed!")
                return -2
            return 2

    def halt():
        nonlocal h, r, hasOutputed

        try:
            sender, halt_msg = halt_recv.get()
            if sender == pid:
                return
            if halt_msg == "dummy":
                return
            halt_tag, halt_msg = halt_msg
            if halt_tag == 'halt' and hasOutputed == False:
                hash_f = hash(str((sid + 'SPBC' + str(halt_msg[0]), halt_msg[2], "FINAL")))
                try:
                    for (k, sig_k) in halt_msg[3]:
                        assert ecdsa_vrfy(PK2s[k], hash_f, sig_k)
                        # assert ecdsa.verify(sig_k, hash_f, PK2s[k], curve=curve.P192)
                except AssertionError:
                    if logger is not None: logger.info("vote Signature failed!")
                    print("vote Signature failed!")

                h = 1
                hasOutputed = True
                send(-2, ('MVBA_HALT', r, r, ("halt", halt_msg)))
                try:
                    decide(halt_msg[2][0])
                except:
                    pass
                try:
                    for i in range(N):
                        spbc_flags[r][i][0] = False
                        spbc_threads[r][i].kill()
                        try:
                            spbc_s1_list[r][i].put_nowait("Dummy")
                        except:
                            pass
                        spbc_s1_threads[r][i].kill()


                    del spbc_recvs[r]
                    del spbc_threads[r]
                    del spbc_s1_threads[r]
                    del spbc_outputs[r]
                    del spbc_s1_list[r]
                    del spbc_flags[r]
                    del s1_list[r]
                    del is_spbc_delivered[r]
                    del is_s1_delivered[r]
                    del aba_recvs
                except:
                    pass
                # recv_loop_thred.kill()
                # if logger is not None: logger.info("%s, round %d smvba decide in halt %f" % (sid, r, time.time()))
        except:
            pass

    halt_recv_thred = gevent.spawn(halt)

    while h == 0:
        gevent.sleep(0.0001)

        spbc_threads[r] = [None] * N
        spbc_outputs[r] = [Queue(1) for _ in range(N)]
        spbc_s1_list[r] = [Queue(1) for _ in range(N)]
        s1_list[r] = [Queue(1) for _ in range(N)]

        is_spbc_delivered[r] = [0] * N
        is_s1_delivered[r] = [0] * N
        spbc_flags[r] = [[True] for _ in range(N)]

        """ 
        Setup the sub protocols Input Broadcast SPBCs"""
        for j in range(N):
            def make_spbc_send(j, r):  # this make will automatically deep copy the enclosed send func
                def spbc_send(k, o):
                    """SPBC send operation.
                    :param k: Node to send.
                    :param o: Value to send.
                    """
                    # print("node", pid, "is sending", o[0], "to node", k, "with the leader", j)
                    send(k, ('MVBA_SPBC', r, j, o))

                return spbc_send

            # Only leader gets input
            spbc_input = my_spbc_input.get if j == pid else None
            if r == 0:
                spbc_threads[r][j] = gevent.spawn(strongprovablebroadcast, sid + 'SPBC' + str(j), pid, N, f, PK2s, SK2,
                                                  j,
                                                  spbc_input, spbc_s1_list[r][j].put_nowait, spbc_recvs[r][j].get,
                                                  make_spbc_send(j, r),
                                                  r, logger, spbc_predicate, spbc_flags[r][j])
            else:
                spbc_threads[r][j] = gevent.spawn(strongprovablebroadcast, sid + 'SPBC' + str(j), pid, N, f, PK2s, SK2,
                                                  j,
                                                  spbc_input, spbc_s1_list[r][j].put_nowait, spbc_recvs[r][j].get,
                                                  make_spbc_send(j, r),
                                                  r, logger, lambda: True, spbc_flags[r][j])

            # cbc.get is a blocking function to get cbc output
            # cbc_outputs[j].put_nowait(cbc.get())
            # gevent.sleep(0)
            # print(pid, "spbc start in round ", r)

        """ 
        Setup the sub protocols permutation coins"""

        def coin_bcast(o):
            """Common coin multicast operation.
            :param o: Value to multicast.
            """
            broadcast(('MVBA_ELECT', r, 'leader_election', o))

        # permutation_coin = shared_coin(sid + 'PERMUTE', pid, N, f,
        #                               PK, SK, coin_bcast, coin_recv.get, single_bit=False)


        """ 
        """
        """ 
        Start to run consensus
        """
        """ 
        """

        """ 
        Run n SPBC instance to consistently broadcast input values
        """

        if r == 0:
            my_msg = input()
            my_spbc_input.put_nowait((my_msg, "null", 0, "first"))

        def get_spbc_s1(leader):
            while h == 0:
                try:
                    out = spbc_s1_list[r][leader].get_nowait()
                except:
                    pass
                try:
                    sid, pid, msg, sigmas1 = out
                except:
                    return
                # print(sid, pid, "finish pcbc in round", r)
                s1_list[r][leader].put_nowait((msg, sigmas1))
                is_s1_delivered[r][leader] = 1

        spbc_s1_threads[r] = [gevent.spawn(get_spbc_s1, node) for node in range(N)]

        wait_spbc_signal = Event()
        wait_spbc_signal.clear()

        def wait_for_spbc_to_continue(leader):
            # Receive output from CBC broadcast for input values
            try:
                msg, sigmas2 = spbc_threads[r][leader].get()
                if predicate(msg[0]):
                    try:
                        spbc_outputs[r][leader].put_nowait((msg, sigmas2))
                        is_spbc_delivered[r][leader] = 1
                        if sum(is_spbc_delivered[r]) == N - f:
                            # gevent.sleep(0.1)
                            wait_spbc_signal.set()
                    except:
                        pass
                else:
                    pass
            except:
                pass

        spbc_out_threads = [gevent.spawn(wait_for_spbc_to_continue, node) for node in range(N)]
        wait_spbc_signal.wait()
        gevent.sleep(0.05)

        try:
            for i in range(N):
                if spbc_threads[r] is not None:
                    spbc_flags[r][i][0] = False
                    spbc_threads[r][i].kill()
                    try:
                        spbc_s1_list[r][i].put_nowait("Dummy")
                    except:
                        pass
                    spbc_s1_threads[r][i].kill()
        except:
            pass
        # print("Node %d finishes n-f SPBC" % pid)
        # print(is_spbc_delivered)

        """
        Run a Coin instance to elect the leaders
        """
        # time.sleep(0.05)
        seed = int.from_bytes(hash(sid + str(r)), byteorder='big') % (2 ** 10 - 1)

        # seed = permutation_coin('permutation')  # Block to get a random seed to permute the list of nodes

        # print("coin has a seed:", seed)
        Leader = seed % N
        Leaders[r] = Leader
        try:
            if is_spbc_delivered[r][Leader] == 1:
                h = 1
                hasOutputed = True
                msg, s2 = spbc_outputs[r][Leader].get()
                halt = (Leader, 2, msg, s2)
                halt_recv.put_nowait((pid, "dummy"))
                send(-2, ('MVBA_HALT', r, pid, ("halt", halt)))
                try:
                    decide(msg[0])
                except:
                    pass
                # if logger is not None and r > 0: logger.info("%s: round %d smvba decide in shortcut. %f" % (sid, r, time.time()))
                break
        except:
            # print("KEY ERROR of is_spbc_delivered! Guess h: " + str(h))
            pass

        try:
            if is_s1_delivered[r][Leader] == 1:
                msg, s1 = s1_list[r][Leader].queue[0]
                prevote = (Leader, 1, msg, s1)
            else:
                digest_no = hash(str((sid, Leader, r, 'pre')))
                prevote = (Leader, 0, "bottom", ecdsa_sign(SK2, digest_no))
                # prevote = (Leader, 0, "bottom", ecdsa.sign(digest_no, SK2, curve=curve.P192))
            broadcast(('MVBA_ABA', r, r, ('prevote', prevote)))
        except:
            # print("KEY ERROR of is_s1_delivered! Guess h: " + str(h))
            pass

        try:
            for i in range(N):
                spbc_flags[r][i][0] = False
                spbc_threads[r][i].kill()
                try:
                    spbc_s1_list[r][i].put_nowait("Dummy")
                except:
                    pass
                spbc_s1_threads[r][i].kill()

            # for j in range(N):
            #    del spbc_recvs[r][j]

            del spbc_recvs[r]
            del spbc_threads[r]
            del spbc_s1_threads[r]
            del spbc_outputs[r]
            del spbc_s1_list[r]
            del spbc_flags[r]
            del s1_list[r]
            del is_spbc_delivered[r]
            del is_s1_delivered[r]

        except:
            pass

        prevote_no_shares = dict()
        vote_yes_shares = dict()
        vote_no_shares = dict()

        hasVoted = False
        while h == 0:
            gevent.sleep(0.0001)
            try:
                sender, aba_msg = aba_recvs[r].get_nowait()
                aba_tag, vote_msg = aba_msg
                if aba_tag == 'prevote' and hasVoted == False and hasOutputed == False:

                    digest_no = hash(str((sid, Leader, r, 'pre')))
                    vote_yes_msg = 0
                    # prevote no
                    if vote_msg[1] != 1:
                        # print(pid, "get prevote no in round", r)
                        try:
                            assert vote_msg[0] == Leader
                            assert ecdsa_vrfy(PK2s[sender], digest_no, vote_msg[3])
                            # assert ecdsa.verify(vote_msg[3], digest_no, PK2s[sender], curve=curve.P192)
                        except AssertionError:
                            if logger is not None: logger.info("pre-vote no failed!")
                            print("pre-vote no failed!")
                            continue
                        prevote_no_shares[sender] = vote_msg[3]
                        if len(prevote_no_shares) == N - f:
                            sigmas_no = tuple(list(prevote_no_shares.items())[:N - f])
                            digest_no_no = hash(str((sid, Leader, r, 'vote')))
                            vote = (Leader, 0, "bottom", sigmas_no, ecdsa_sign(SK2, digest_no_no))
                            # vote = (Leader, 0, "bottom", sigmas_no, ecdsa.sign(digest_no_no, SK2, curve=curve.P192))
                            broadcast(('MVBA_ABA', r, r, ('vote', vote)))
                            hasVoted = True

                    elif vote_msg[1] == 1:
                        try:
                            assert vote_msg[0] == Leader
                        except AssertionError:
                            if logger is not None: logger.info("pre-vote Signature failed!")
                            print("pre-vote Signature failed!")
                            continue
                        pii = hash(str((sid + 'SPBC' + str(Leader), vote_msg[2], "FINAL")))
                        vote = (Leader, 1, vote_msg[2], vote_msg[3], ecdsa_sign(SK2, pii))
                        # vote = (Leader, 1, vote_msg[2], vote_msg[3], ecdsa.sign(pii, SK2, curve=curve.P192))

                        broadcast(('MVBA_ABA', r, r, ('vote', vote)))
                        hasVoted = True

                # vote yes
                if aba_tag == 'vote' and hasOutputed == False:
                    if vote_msg[1] == 1:
                        if vote_msg[0] != Leader:
                            print("wrong Leader")
                            if logger is not None: logger.info("wrong Leader")

                        hash_e = hash(str((sid + 'SPBC' + str(Leader), vote_msg[2], "ECHO")))
                        try:
                            for (k, sig_k) in vote_msg[3]:
                                assert ecdsa_vrfy(PK2s[k],hash_e, sig_k)
                                # assert ecdsa.verify(sig_k, hash_e, PK2s[k], curve=curve.P192)
                            # assert ecdsa.verify(vote_msg[4],
                            #                     hash(str((sid + 'SPBC' + str(Leader), vote_msg[2], "FINAL"))),
                            #                     PK2s[sender], curve=curve.P192)
                            assert ecdsa_vrfy(PK2s[sender], hash(str((sid + 'SPBC' + str(Leader), vote_msg[2], "FINAL"))), vote_msg[4])
                        except AssertionError:
                            if logger is not None: logger.info("vote Signature failed!")
                            # print("vote Signature failed!")
                            continue

                        vote_yes_shares[sender] = vote_msg[4]
                        vote_yes_msg = vote_msg[2]
                        # 2f+1 vote yes
                        if len(vote_yes_shares) == N - f:
                            hasOutputed = True
                            h = 1
                            halt_msg = (Leader, 2, vote_msg[2], tuple(list(vote_yes_shares.items())[:N - f]))
                            halt_recv.put_nowait((pid, "dummy"))
                            send(-2, ('MVBA_HALT', r, pid, ("halt", halt_msg)))
                            try:
                                decide(vote_msg[2][0])
                            except:
                                pass
                            break

                    # vote no
                    if vote_msg[1] == 0:
                        if vote_msg[0] != Leader:
                            print("wrong Leader")
                            if logger is not None: logger.info("wrong Leader")

                        hash_pre = hash(str((sid, Leader, r, 'pre')))
                        try:
                            # vrify sigmas_no
                            for (k, sig_k) in vote_msg[3]:
                                ecdsa_vrfy(PK2s[k], hash_pre, sig_k)
                                # ecdsa.verify(sig_k, hash_pre, PK2s[k], curve=curve.P192)
                            # vrify no_no
                            digest_no_no = hash(str((sid, Leader, r, 'vote')))
                            assert ecdsa_vrfy(PK2s[sender], digest_no_no, vote_msg[4])
                            # assert ecdsa.verify(vote_msg[4], digest_no_no, PK2s[sender], curve=curve.P192)
                        except AssertionError:
                            if logger is not None: logger.info("vote no failed!")
                            print(pid, "vote no failed! sigmas in round", r)
                            continue

                        vote_no_shares[sender] = vote_msg[4]
                        if len(vote_no_shares) == N - f:
                            pis = tuple(list(vote_no_shares.items())[:N - f])
                            my_spbc_input.put_nowait((my_msg, pis, r, 'no'))
                            r += 1
                            prevote_no_shares.clear()
                            vote_yes_shares.clear()
                            vote_no_shares.clear()
                            break
                    # both vote no and vote yes
                    if (len(vote_no_shares) > 0) and (len(vote_yes_shares) > 0):
                        my_spbc_input.put_nowait((vote_yes_msg[0], vote_msg[3], r, 'yn'))
                        r += 1
                        prevote_no_shares.clear()
                        vote_yes_shares.clear()
                        vote_no_shares.clear()
                        # r = r % 10
                        break
            except:
                pass

    recv_loop_thred.kill()
    halt_recv_thred.kill()
    del halt_recv
    del aba_recvs
