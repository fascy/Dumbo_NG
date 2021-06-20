import hashlib, pickle
from crypto.ecdsa.ecdsa import ecdsa_vrfy

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def pb_validate(sid, N, f, PK2s, proof):
    try:
        pb_sid, digest, sigmas = proof
        assert pb_sid == sid
        assert len(sigmas) == N - f and len(set(sigmas)) == N - f
        d = hash((sid, digest))
        for (i, sig_i) in sigmas:
            assert ecdsa_vrfy(PK2s[i], d, sig_i)
        return True
    except:
        return False