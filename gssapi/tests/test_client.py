import unittest
import should_be.all  # noqa
import gssapi.client as gc
import gssapi.base as gb
import socket


TARGET_SERVICE_NAME = 'host'
INITIATOR_PRINICIPLE = 'admin'


class FakeServer(object):
    def __init__(self):
        self.ctx = None
        str_server_name = (TARGET_SERVICE_NAME.encode('utf-8') + b'/' +
                           socket.getfqdn().encode('utf-8'))
        self.server_name = gb.importName(str_server_name,
                                         gb.NameType.principal)
        self.server_creds = gb.acquireCred(self.server_name)[0]

    def process_token(self, tok):
        server_resp = gb.acceptSecContext(tok,
                                          acceptor_cred=self.server_creds)
        self.ctx = server_resp[0]
        return server_resp[3]

    def decrypt(self, msg):
        return gb.unwrap(self.ctx, msg)[0].decode('utf-8')

    def encrypt(self, msg):
        return gb.wrap(self.ctx, msg.encode('utf-8'), True, None)[0]


class TestBasicClient(unittest.TestCase):
    def setUp(self):
        self.client = gc.BasicGSSClient(TARGET_SERVICE_NAME)
        self.server = FakeServer()

    def test_basic_client_setup(self):
        self.client.shouldnt_be_none()
        self.client.should_be_a(gc.BasicGSSClient)

        self.client.service_name.should_be_a('GSSName')

        self.client.security_type.should_be(gb.RequirementFlag.confidentiality)

    def test_token_process(self):
        init_token = self.client.setupBaseSecurityContext()

        init_token.should_be_a(bytes)
        init_token.shouldnt_be_empty()

        self.client.ctx.shouldnt_be_none()
        self.client.ctx.should_be_a(gb.SecurityContext)

        self.client.last_ttl.should_be_a(int)

        # "send" the token and get one back
        server_token = self.server.process_token(init_token)

        final_token = self.client.updateSecurityContext(server_token)

        final_token.should_be_a(bytes)

    def test_encrypt_decrypt(self):
        init_token = self.client.setupBaseSecurityContext()
        server_token = self.server.process_token(init_token)
        self.client.updateSecurityContext(server_token)

        enc_client_msg = self.client.encrypt('msg1')

        enc_client_msg.should_be_a(bytes)
        enc_client_msg.shouldnt_be_empty()
        enc_client_msg.should_be_longer_than('msg1')

        dec_client_msg = self.server.decrypt(enc_client_msg)
        dec_client_msg.should_be('msg1')

        enc_server_msg = self.server.encrypt('msg2')
        dec_server_msg = self.client.decrypt(enc_server_msg)

        dec_server_msg.should_be_a(str)
        dec_server_msg.should_be('msg2')
