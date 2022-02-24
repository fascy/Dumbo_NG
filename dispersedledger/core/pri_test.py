import time
from multiprocessing.managers import BaseManager
from multiprocessing import Process

from queue import PriorityQueue
from random import randint


class Manger(BaseManager):
    pass


Manger.register('get_priorityQueue', PriorityQueue)

def double(n):
    return n * 2

def producer(q):
    count = 0
    while 1:
        if count > 100:
            break
        pri = randint(0, 1)
        print("put", pri)
        if pri == 1:
            msg = "this is a low pri msg"
        else:
            msg = "this is a high pri msg"
        q.put((pri, msg))
        count += 1
        time.sleep(0.001)

def consumer(q):
    while 1:
        if q.empty():
            break
        pri, msg = q.get()
        print(pri, msg)
        q.task_done()
        time.sleep(0.001)

m = Manger()
m.start()
q = m.get_priorityQueue()
t = Process(target=producer, args=(q,))
t2 = Process(target=consumer, args=(q,))
t.start()
t2.start()
t2.join()