import traceback

from gevent import monkey; monkey.patch_all(thread=False)

from datetime import datetime
import gevent


def speedydumbocommonsubset(pid, N, f, pb_values_out, pb_proof_out, vacs_in, vacs_out, logger=None):
    """The BKR93 algorithm for asynchronous common subset.

    :param pid: my identifier
    :param N: number of nodes
    :param f: fault tolerance
    :param rbc_out: an array of :math:`N` (blocking) output functions,
        returning a string
    :param aba_in: an array of :math:`N` (non-blocking) functions that
        accept an input bit
    :param aba_out: an array of :math:`N` (blocking) output functions,
        returning a bit
    :return: an :math:`N`-element array, each element either ``None`` or a
        string
    """

    #print("Starts to run dumbo ACS...")

    #assert len(prbc_out) == N
    #assert len(vacs_in) == 1
    #assert len(vacs_out) == 1

    pb_values = [None] * N

    def wait_for_pb_proof():#
        # Receive output from reliable broadcast
        (prbc_sid, digest, Sigma) = pb_proof_out()
        prbc_proof = (prbc_sid, digest, Sigma)
        vacs_in(prbc_proof)
        # if logger != None:
        #     logger.info("DumboACS transfers prbc out to vacs in at %s" % datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])
        # print("node %d get PB proof in ACS" % pid)

    def wait_for_pb_value(leader):
        msg = pb_values_out[leader]()
        assert msg is not None
        pb_values[leader] = msg
        #print("node %d get PB value in ACS from leader %d" % (pid, leader))

    pb_proof_thread = gevent.spawn(wait_for_pb_proof)
    pb_value_threads = [gevent.spawn(wait_for_pb_value, i) for i in range(N)]

    # Block to wait VACS output a vector of chosen PB proofs
    pb_proofs_vector = vacs_out()

    if pb_proofs_vector is not None:
        #assert type(prbc_proofs_vector) == list and len(prbc_proofs_vector) == N
        for j in range(N):
            if pb_proofs_vector[j] is not None:
                   # TODO: It is possible never wait the delivered pb value, so there shall be a help function to allow retrive
                try:
                    assert pb_values[j] is not None   # TODO: Check delivered value consistent to pb proof
                    #print("node %d collects one more value in ACS 1 from leader %d" % (pid, j))
                except AssertionError as e:
                    #print("node %d finds None PB value in ACS from leader %d" % (pid, j))
                    pb_value_threads[j].join()
                    assert pb_values[j] is not None
                    #print("node %d collects one more value in ACS 2 from leader %d" % (pid, j))
                    #traceback.print_exc()
                    pass
            else:
                pb_value_threads[j].kill()
                pb_values[j] = None

    #print("node %d output in ACS" % pid)
    pb_proof_thread.kill()
    return tuple(pb_values)
