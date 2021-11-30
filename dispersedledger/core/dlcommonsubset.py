from gevent import monkey; monkey.patch_all(thread=False)

from datetime import datetime
import gevent


def dlcommonsubset(pid, N, f, pcbc_out, vacs_in, vacs_out, logger=None):
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

    pcbc_values = [None] * N
    pcbc_proofs = [None] * N
    is_pcbc_delivered = [0] * N

    def wait_for_pcbc_to_continue(leader):#
        # Receive output from reliable broadcast
        (chunk, proof, root), sigmas = pcbc_out[leader]()
        pcbc_values[leader] = (chunk, proof, root)
        pcbc_proofs[leader] = (root, sigmas)
        is_pcbc_delivered[leader] = 1
        if leader == pid:
            vacs_in(pcbc_proofs[leader])
            if logger != None:
                logger.info("DLACS transfers pcbc out to vacs in at %s" % datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])

    pcbc_threads = [gevent.spawn(wait_for_pcbc_to_continue, j) for j in range(N)]

    pcbc_proofs_vector = vacs_out()

    if pcbc_proofs_vector is not None:
        #assert type(prbc_proofs_vector) == list and len(prbc_proofs_vector) == N
        for j in range(N):
            if pcbc_proofs_vector[j] is not None:
                pcbc_threads[j].join()
                assert pcbc_values[j] is not None
            else:
                pcbc_threads[j].kill()
                pcbc_values[j] = None

    return tuple(pcbc_values)
