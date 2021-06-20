from crypto.threshsig.boldyreva import dealer
import pickle

PK, SKs = dealer(players=16, k=5)

h = PK.hash_message('hi')

for SK in SKs:
    sig = SK.sign(h)
    print(PK.verify_share(sig, SK.i, h))

PK = pickle.loads(pickle.dumps(PK))

for SK in SKs:
    SK = pickle.loads(pickle.dumps(SK))
    sig = SK.sign(h)
    print(PK.verify_share(sig, SK.i, h))
