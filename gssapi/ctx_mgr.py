from __future__ import print_function
import gssapi.base as gb
import gssapi.client as gcl

import socket

class GSSSocketClient(object):
    def __init__(self, target, sock=None,
                 sender=None, recver=None, **kwargs):

        if sock is None:
            self.socket = socket.socket()

            service_name, service_host = target.split('@')
            service_host = service_host or 'localhost'

            port = socket.getservbyname(service_name)
            host = socket.gethostbyname(service_host)

            self.socket.connect((host, port))
            self.was_our_socket = True
        else:
            self.socket = sock
            self.was_our_socket = False

        self.client = gcl.BasicGSSClient(target, **kwargs)

        if sender is None:
            def default_sender(enc_msg, func):
                return func(enc_msg)

            self.sender = default_sender

        if recver is None:
            def default_recver(func):
                return func(1000)

            self.recver = default_recver

        self._init_gss_conn()

    def _init_gss_conn(self):
        client_tok = self.client.createDefaultToken()
        self.sender(client_tok, self.socket.send)
        server_tok = self.recver(self.socket.recv)
        self.client.processServerToken(server_tok)

    def send(self, msg):
       enc_msg = self.client.wrap(msg)
       return self.sender(enc_msg, self.socket.send)

    def recv(self):
        enc_msg = self.recver(self.socket.recv)
        return self.client.unwrap(enc_msg)

    def __del__(self):
        if self.was_our_socket:
            self.socket.close()

        del self.client

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.__del__()


def open(*args, **kwargs):
    return GSSSocketClient(*args, **kwargs)
