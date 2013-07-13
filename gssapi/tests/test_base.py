import unittest
import should_be.all  # noqa
import socket
import gssapi.base as gb


TARGET_SERVICE_NAME = 'admin'
INITIATOR_PRINICIPLE = 'admin'


class TestBaseUtilities(unittest.TestCase):
    def test_import_name(self):
        imported_name = gb.importName('vnc')

        imported_name.shouldnt_be_none()
        imported_name.should_be_a('PyCapsule')

        gb.releaseName(imported_name)

    def test_get_mech_type(mech_type):
        mech_type = gb.getMechanismType(gb.MechType.kerberos)

        mech_type.shouldnt_be_none()
        mech_type.should_be_a('PyCapsule')

    def test_display_status(self):
        status_resp = gb.displayStatus(0, False)
        status_resp.shouldnt_be_none()

        (status, ctx, cont) = status_resp

        status.should_be_a(str)
        status.shouldnt_be_empty()

        ctx.should_be_a(int)

        cont.should_be_a(bool)
        cont.should_be_false()

    def test_acquire_creds(self):
        name = gb.importName('host/sross.localdomain', gb.NameType.principal)
        cred_resp = gb.acquireCred(name)
        cred_resp.shouldnt_be_none()

        (creds, actual_mechs, ttl) = cred_resp

        creds.shouldnt_be_none()
        creds.should_be_a('PyCapsule')

        actual_mechs.shouldnt_be_empty()
        actual_mechs.should_include(gb.MechType.kerberos)

        ttl.should_be_a(int)

        gb.releaseName(name)
        gb.releaseCred(creds)


class TestInitContext(unittest.TestCase):
    def setUp(self):
        self.target_name = gb.importName('host')

    def tearDown(self):
        gb.releaseName(self.target_name)

    def test_basic_init_default_ctx(self):
        ctx_resp = gb.initSecContext(self.target_name)
        ctx_resp.shouldnt_be_none()

        (ctx, out_mech_type,
         out_req_flags, out_token, out_ttl, cont_needed) = ctx_resp

        ctx.shouldnt_be_none()
        ctx.should_be_a('PyCapsule')

        out_mech_type.should_be(gb.MechType.kerberos)

        out_req_flags.should_be_a(list)
        out_req_flags.should_be_at_least_length(2)

        out_token.shouldnt_be_empty()

        out_ttl.should_be_greater_than(0)

        cont_needed.should_be_a(bool)

        gb.deleteSecContext(ctx)


class TestAcceptContext(unittest.TestCase):

    def setUp(self):
        self.target_name = gb.importName('host')
        ctx_resp = gb.initSecContext(self.target_name)

        self.client_token = ctx_resp[3]
        self.client_ctx = ctx_resp[0]

        self.server_name = gb.importName('host/'+socket.getfqdn(),
                                         gb.NameType.principal)
        self.server_creds = gb.acquireCred(self.server_name)[0]

        self.server_ctx = None

    def tearDown(self):
        gb.releaseName(self.target_name)
        gb.releaseName(self.server_name)
        gb.releaseCred(self.server_creds)
        gb.deleteSecContext(self.client_ctx)

        if self.server_ctx is not None:
            gb.deleteSecContext(self.server_ctx)

    def test_basic_accept_context(self):
        server_resp = gb.acceptSecContext(self.client_token,
                                          acceptor_cred=self.server_creds)
        server_resp.shouldnt_be_none()

        (self.server_ctx, name, mech_type, out_token,
         out_req_flags, out_ttl, delegated_cred, cont_needed) = server_resp

        self.server_ctx.shouldnt_be_none()
        self.server_ctx.should_be_a('PyCapsule')

        name.shouldnt_be_none()
        name.should_be_a('PyCapsule')

        mech_type.should_be(gb.MechType.kerberos)

        out_token.shouldnt_be_empty()

        out_req_flags.should_be_a(list)
        out_req_flags.should_be_at_least_length(2)

        out_ttl.should_be_greater_than(0)

        if delegated_cred is not None:
            delegated_cred.should_be_a('PyCapsule')

        cont_needed.should_be_a(bool)


class TestWrapUnwrap(unittest.TestCase):
    def setUp(self):
        self.target_name = gb.importName('host')
        ctx_resp = gb.initSecContext(self.target_name)

        self.client_token1 = ctx_resp[3]
        self.client_ctx = ctx_resp[0]

        self.server_name = gb.importName('host/'+socket.getfqdn(),
                                         gb.NameType.principal)
        self.server_creds = gb.acquireCred(self.server_name)[0]
        server_resp = gb.acceptSecContext(self.client_token1,
                                          acceptor_cred=self.server_creds)
        self.server_ctx = server_resp[0]
        self.server_tok = server_resp[3]

        client_resp2 = gb.initSecContext(self.target_name,
                                         context=self.client_ctx,
                                         input_token=self.server_tok)
        self.client_token2 = client_resp2[3]
        self.client_ctx = client_resp2[0]

    def tearDown(self):
        gb.releaseName(self.target_name)
        gb.releaseName(self.server_name)
        gb.releaseCred(self.server_creds)
        gb.deleteSecContext(self.client_ctx)
        gb.deleteSecContext(self.server_ctx)

    def test_basic_wrap_unwrap(self):
        (wrapped_message, conf) = gb.wrap(self.client_ctx, 'test message')

        conf.should_be_a(bool)
        conf.should_be_true()

        wrapped_message.should_be_a(bytes)
        wrapped_message.shouldnt_be_empty()
        wrapped_message.should_be_longer_than('test message')

        (unwrapped_message, conf, qop) = gb.unwrap(self.server_ctx,
                                                   wrapped_message)
        conf.should_be_a(bool)
        conf.should_be_true()

        qop.should_be_a(int)
        qop.should_be_at_least(0)

        unwrapped_message.should_be_a(str)
        unwrapped_message.shouldnt_be_empty()
        unwrapped_message.should_be('test message')
