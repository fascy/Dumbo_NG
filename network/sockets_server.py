import gevent
from gevent import monkey;

monkey.patch_all(thread=False)

from gevent.server import StreamServer
import pickle
from typing import Callable
import os
import logging
import traceback
from multiprocessing import Value as mpValue, Process


# Network node class: deal with socket communications
class NetworkServers(Process):
    SEP = '\r\nSEP\r\nSEP\r\nSEP\r\n'.encode('utf-8')

    def __init__(self, port1: int, port2: int, my_ip1: str, my_ip2: str, id: int, addresses_list1: list,
                 addresses_list2: list,
                 server_to_bft1: Callable, server_to_bft2: Callable, server_ready1: mpValue, server_ready2: mpValue,
                 stop1: mpValue, stop2: mpValue, win1=1, win2=2):

        self.server_to_bft1 = server_to_bft1
        self.server_to_bft2 = server_to_bft2
        self.ready1 = server_ready1
        self.ready2 = server_ready2
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
        self.is_in_sock_connected1 = [False] * self.N
        self.is_in_sock_connected2 = [False] * self.N
        self.socks1 = [None for _ in self.addresses_list1]
        self.socks2 = [None for _ in self.addresses_list2]
        self.win1 = win1
        self.win2 = win2
        super().__init__()

    def _listen_and_recv_forever(self, ip, port, stop, win, server_to_bft, addresses_list):
        pid = os.getpid()
        self.logger.info(
            'node %d\'s socket server starts to listen ingoing connections on process id %d' % (self.id, pid))
        print("my IP is " + ip)

        def _handler(sock, address):
            jid = self._address_to_id(address, addresses_list)
            buf = b''
            try:
                while not stop.value:
                    if True:
                        buf += sock.recv(106496)
                    else:
                        buf += sock.recv(25600)
                        # buf += sock.recv(106496)
                    tmp = buf.split(self.SEP, 1)
                    while len(tmp) == 2:
                        buf = tmp[1]
                        data = tmp[0]
                        if data != '' and data:
                            (j, o) = (jid, pickle.loads(data))
                            # assert j in range(self.N)
                            server_to_bft((j, o))
                            # self.logger.info('recv' + str((j, o)))
                            # print('recv' + str((j, o)))
                        else:
                            self.logger.error('syntax error messages')
                            raise ValueError
                        tmp = buf.split(self.SEP, 1)
                    # gevent.sleep(0)
            except Exception as e:
                self.logger.error(str((e, traceback.print_exc())))

        self.streamServer = StreamServer((ip, port), _handler)
        self.streamServer.serve_forever()

    def run(self):
        pid = os.getpid()
        self.logger = self._set_server_logger(self.id)
        self.logger.info('node id %d is running on pid %d' % (self.id, pid))
        with self.ready1.get_lock():
            self.ready1.value = False
        sever1 = gevent.spawn(self._listen_and_recv_forever, self.ip1, self.port1, self.stop1, self.win1, self.server_to_bft1,
                              self.addresses_list1)
        with self.ready2.get_lock():
            self.ready2.value = False
        sever2 = gevent.spawn(self._listen_and_recv_forever, self.ip2, self.port2, self.stop2, self.win2, self.server_to_bft2,
                              self.addresses_list2)
        sever1.join()
        sever2.join()

    def _address_to_id(self, address: tuple, addresses_list):
        for i in range(self.N):
            if address[0] != '127.0.0.1' and address[0] == addresses_list[i][0]:
                # print("333333333", i)
                return i
        # print(address[1], address[0])
        # print("3333", int((address[1] - 10000) / 200))
        return int((address[1] - 10000) / 200)

    def _set_server_logger(self, id: int):
        logger = logging.getLogger("node-" + str(id))
        logger.setLevel(logging.DEBUG)
        # logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
        if 'log' not in os.listdir(os.getcwd()):
            os.mkdir(os.getcwd() + '/log')
        full_path = os.path.realpath(os.getcwd()) + '/log/' + "node-net-server-" + str(id) + ".log"
        file_handler = logging.FileHandler(full_path)
        file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
        logger.addHandler(file_handler)
        return logger
