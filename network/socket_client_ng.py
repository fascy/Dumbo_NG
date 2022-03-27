from gevent import monkey;

monkey.patch_all(thread=False)

import time
import pickle
from typing import List, Callable
import gevent
import os
from multiprocessing import Value as mpValue, Process
from gevent import socket, lock
from gevent.queue import Queue, PriorityQueue
import logging
import traceback


# Network node class: deal with socket communications
class NetworkClient(Process):
    SEP = '\r\nSEP\r\nSEP\r\nSEP\r\n'.encode('utf-8')

    def __init__(self, port: int, my_ip: str, id: int, addresses_list: list, client_from_bft: Callable,
                 client_ready: mpValue, stop: mpValue, s=0):

        self.client_from_bft = client_from_bft
        self.ready = client_ready
        self.stop = stop

        self.ip = my_ip
        self.port = port
        self.id = id
        self.addresses_list = addresses_list
        self.N = len(self.addresses_list)

        self.is_out_sock_connected = [False] * self.N

        self.socks = [None for _ in self.addresses_list]
        self.sock_queues = [Queue() for _ in self.addresses_list]

        self.sock_locks = [lock.Semaphore() for _ in self.addresses_list]
        self.s = s
        self.BYTES = 5000
        super().__init__()

    def _connect_and_send_forever(self):
        pid = os.getpid()
        self.logger.info(
            'node %d\'s socket client starts to make outgoing connections on process id %d' % (self.id, pid))
        while not self.stop.value:
            try:
                for j in range(self.N):
                    if not self.is_out_sock_connected[j]:
                        self.is_out_sock_connected[j] = self._connect(j)
                if all(self.is_out_sock_connected):
                    with self.ready.get_lock():
                        self.ready.value = True
                    break
            except Exception as e:
                self.logger.info(str((e, traceback.print_exc())))
        send_threads = [gevent.spawn(self._send, j) for j in range(self.N)]

        self._handle_send_loop()
        # gevent.joinall(send_threads)

    def _connect(self, j: int):
        sock = socket.socket()
        if self.ip == '127.0.0.1':
            # print(self.ip"bind", self.port + j + 1)
            sock.bind((self.ip, self.port + j + 1))
        try:
            sock.connect(self.addresses_list[j])
            self.socks[j] = sock
            return True
        except Exception as e1:
            self.logger.error(str(j)+str((e1, traceback.print_exc())))
            return False

    def _send(self, j: int):
        while not self.stop.value:
            gevent.sleep(0.005)
            # self.sock_locks[j].acquire()
            p, _, o = self.sock_queues[j].get()
            while True:
                try:
                    # time.sleep(int(self.id) * 0.01)
                    msg = pickle.dumps(o)
                    self.socks[j].sendall(msg + self.SEP)
                    break
                except Exception as e:
                    self.logger.error("fail to send msg")
                    if o[1][0] == 'X_VABA':
                        self.logger.error(str((j, o[1][0], o[0])))
                    else:
                        self.logger.error(str((j, o[1][0], o[1][2])))
                    self.logger.error(str((e, traceback.print_exc())))
                    gevent.sleep(0.001)
                    self._connect(j)
                    continue
                    # self.socks[j].close()
                    # self.sock_locks[j].release()

    ##
    def _handle_send_loop(self):
        while not self.stop.value:
            try:

                j, o = self.client_from_bft()
                # print("！！！！！！！！！！！！1", j, o)

                try:
                    #self._send(j, pickle.dumps(o))
                    if j == -1: # -1 means broadcast
                        if o[1][0] == 'X_VABA':
                            for i in range(self.N):
                                self.sock_queues[i].put_nowait((-1,0,o))
                        elif o[1][0] == 'PROPOSAL':
                            slot = o[1][2]
                            for i in range(self.N):
                                self.sock_queues[i].put_nowait((1,-o[1][2],o))
                        else:
                            for i in range(self.N):
                                self.sock_queues[i].put_nowait((1,0,o))
                    elif j == -2: # -2 means broadcast except myself
                        if o[1][0] == 'X_VABA':
                            for i in range(self.N):
                                self.sock_queues[i].put_nowait((-2,0,o))
                        else:
                            for i in range(self.N):
                                self.sock_queues[i].put_nowait((1,0,o))
                    else:
                        if o[1][0] == 'X_VABA':
                            self.sock_queues[j].put_nowait((-1,0,o))
                        else:
                            self.sock_queues[j].put_nowait((1,0,o))
                except Exception as e:
                    self.logger.error(str(("problem objective when sending", o)))
                    traceback.print_exc()
            except:
                pass
        # print("sending loop quits ...")

    def run(self):
        self.logger = self._set_client_logger(self.id)
        pid = os.getpid()
        self.logger.info('node id %d is running on pid %d' % (self.id, pid))
        with self.ready.get_lock():
            self.ready.value = False
        conn_thread = gevent.spawn(self._connect_and_send_forever)
        conn_thread.join()

    def stop_service(self):
        with self.stop.get_lock():
            self.stop.value = True

    def _set_client_logger(self, id: int):
        logger = logging.getLogger("node-" + str(id))
        logger.setLevel(logging.DEBUG)
        # logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
        if 'log' not in os.listdir(os.getcwd()):
            os.mkdir(os.getcwd() + '/log')
        full_path = os.path.realpath(os.getcwd()) + '/log/' + "node-net-client-" + str(id) + ".log"
        file_handler = logging.FileHandler(full_path)
        file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
        logger.addHandler(file_handler)
        return logger