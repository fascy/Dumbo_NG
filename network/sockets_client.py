from gevent import monkey;

monkey.patch_all(thread=False)

import time
import pickle
from typing import List, Callable
import gevent
import os
from multiprocessing import Value as mpValue, Process
from gevent import socket, lock
from gevent.queue import Queue
import logging
import traceback


# Network node class: deal with socket communications
class NetworkClients(Process):
    SEP = '\r\nSEP\r\nSEP\r\nSEP\r\n'.encode('utf-8')

    def __init__(self, port1: int, port2: int, my_ip1: str, my_ip2: str, id: int, addresses_list1: list, addresses_list2: list,
                 client_from_bft1: Callable, client_from_bft2: Callable,
                 client_ready1: mpValue, client_ready2: mpValue, stop1: mpValue , stop2: mpValue, s1=0, s2=1):

        self.client_from_bft1 = client_from_bft1
        self.client_from_bft2 = client_from_bft2
        self.ready1 = client_ready1
        self.ready2 = client_ready2
        self.stop1 = stop1
        self.stop2 = stop2

        self.ip1 = my_ip1
        self.ip2 = my_ip2
        self.port1 = port1
        self.port2 = port2
        self.id = id
        self.addresses_list1 = addresses_list1
        self.addresses_list2 = addresses_list2
        self.N = len(self.addresses_list1)

        self.is_out_sock_connected1 = [False] * self.N
        self.is_out_sock_connected2 = [False] * self.N

        self.socks1 = [None for _ in self.addresses_list1]
        self.socks2 = [None for _ in self.addresses_list2]
        self.sock_queues1 = [Queue() for _ in self.addresses_list1]
        self.sock_queues2 = [Queue() for _ in self.addresses_list2]

        self.sock_locks1 = [lock.Semaphore() for _ in self.addresses_list1]
        self.sock_locks2 = [lock.Semaphore() for _ in self.addresses_list2]
        self.s1 = s1
        self.s2 = s2
        self.BYTES = 10000
        super().__init__()

    def _connect_and_send_forever(self, is_out_sock_connected, ready, ip, port, addresses_list, socks, s, stop,
                                  sock_queues, client_from_bft):
        pid = os.getpid()
        self.logger.info(
            'node %d\'s socket client starts to make outgoing connections on process id %d' % (self.id, pid))
        while not stop.value:
            try:
                for j in range(self.N):
                    if not is_out_sock_connected[j]:
                        is_out_sock_connected[j] = self._connect(j, ip, port, addresses_list, socks)
                if all(is_out_sock_connected):
                    with ready.get_lock():
                        ready.value = True
                    break
            except Exception as e:
                self.logger.info(str((e, traceback.print_exc())))
        send_threads = [gevent.spawn(self._send, j, s, stop, sock_queues, socks) for j in range(self.N)]
        self._handle_send_loop(stop, client_from_bft, sock_queues)
        # gevent.joinall(send_threads)

    def _connect(self, j: int, ip, port, addresses_list, socks):
        sock = socket.socket()
        if ip == '127.0.0.1':
            # print(self.ip"bind", self.port + j + 1)
            sock.bind((ip, port + j + 1))
        try:
            sock.connect(addresses_list[j])
            socks[j] = sock
            return True
        except Exception as e1:
            return False

    def _send(self, j: int, s, stop, sock_queues, socks):
        if s == 1:
            cnt = self.BYTES  # 1000 bytes
            msg = None

            while not stop.value:

                if msg is None:
                    o = sock_queues[j].get()
                    msg = pickle.dumps(o) + self.SEP

                if len(msg) <= cnt:
                    cnt = cnt - len(msg)
                    try:
                        socks[j].sendall(msg)
                        msg = None
                    except:
                        self.logger.error("fail to send msg")
                        # self.logger.error(str((e1, traceback.print_exc())))
                        socks[j].close()
                        break
                else:
                    msg1 = msg[0:cnt]
                    msg = msg[cnt:]
                    try:
                        socks[j].sendall(msg1)
                        cnt = 0
                    except:
                        self.logger.error("fail to send msg")
                        # self.logger.error(str((e1, traceback.print_exc())))
                        socks[j].close()
                        break

                if cnt == 0:
                    cnt = self.BYTES
                    if s == 1:
                        gevent.sleep(0.001)
        else:
            while not stop.value:
                # gevent.sleep(0)
                # self.sock_locks[j].acquire()
                o = sock_queues[j].get()
                try:
                    # time.sleep(int(self.id) * 0.01)
                    msg = pickle.dumps(o)
                    socks[j].sendall(msg + self.SEP)
                except:
                    self.logger.error("fail to send msg")
                    # self.logger.error(str((e1, traceback.print_exc())))
                    socks[j].close()
                    break
                # self.sock_locks[j].release()

    ##
    def _handle_send_loop(self, stop, client_from_bft, sock_queues):
        while not stop.value:
            try:

                j, o = client_from_bft()
                # o = self.send_queue[j].get_nowait()

                # self.logger.info('send' + str((j, o)))
                try:
                    # self._send(j, pickle.dumps(o))
                    if j == -1:  # -1 means broadcast
                        for i in range(self.N):
                            sock_queues[i].put_nowait(o)
                    elif j == -2:  # -2 means broadcast except myself
                        for i in range(self.N):
                            if i != self.pid:
                                sock_queues[i].put_nowait(o)
                    else:
                        sock_queues[j].put_nowait(o)
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
        with self.ready1.get_lock():
            self.ready1.value = False
        conn_thread1 = gevent.spawn(self._connect_and_send_forever, self.is_out_sock_connected1, self.ready1, self.ip1, self.port1,
                                   self.addresses_list1, self.socks1, self.s1, self.stop1,
                                   self.sock_queues1, self.client_from_bft1)

        with self.ready2.get_lock():
            self.ready2.value = False
        conn_thread2 = gevent.spawn(self._connect_and_send_forever, self.is_out_sock_connected2, self.ready2, self.ip2,
                                    self.port2,
                                    self.addresses_list2, self.socks2, self.s2, self.stop2,
                                    self.sock_queues2, self.client_from_bft2)
        # conn_thread1.join()
        conn_thread2.join()

    def stop_service(self, stop):
        with stop.get_lock():
            stop.value = True

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
