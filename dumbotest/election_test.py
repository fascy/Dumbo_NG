import numpy as np
from gevent.event import Event
import gevent
import time
from gevent import monkey
from gevent.queue import Queue
monkey.patch_all(thread=False)

rc_ballot = [0 for n in range(10)]

def change():
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    for i in range(10):
        rc_ballot[i] = 1
        print(rc_ballot)


change_thread = gevent.spawn(change)
# print(change_thread.get())
# rc_ballot = change_thread.get()
wait_rcballot_signal = Event()
wait_rcballot_signal.clear()



def wait_for_finish_to_continue():
    print(rc_ballot[1])
    if sum(rc_ballot) >= 3:
        wait_rcballot_signal.set()
        # print("Leader %d finishes CBC for node %d" % (leader, pid) )
        print(rc_ballot)


finish_out_thread = gevent.spawn(wait_for_finish_to_continue)
wait_rcballot_signal.wait()

