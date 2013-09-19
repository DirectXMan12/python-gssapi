import unittest
import should_be.all  # noqa
import socket
import gssapi.base as gb


TARGET_SERVICE_NAME = b'host'
INITIATOR_PRINCIPAL = b'admin'


class TestBaseUtilities(unittest.TestCase):
    def test_indicate_mechs(self):
        mechs = gb.indicateMechs()

        mechs.shouldnt_be_none()
        mechs.should_be_a(list)

        mechs.shouldnt_be_empty()
        mechs.should_include(gb.MechType.kerberos)

    def test_import_name(self):
        imported_name = gb.importName(TARGET_SERVICE_NAME)

        imported_name.shouldnt_be_none()
        imported_name.should_be_a(gb.Name)

        gb.releaseName(imported_name)

    def test_canonicalize_export_name(self):
        imported_name = gb.importName(INITIATOR_PRINCIPAL,
                                      gb.NameType.principal)

        canonicalized_name = gb.canonicalizeName(imported_name,
                                                 gb.MechType.kerberos)

        canonicalized_name.shouldnt_be_none()
        canonicalized_name.should_be_a(gb.Name)

        exported_name = gb.exportName(canonicalized_name)

        exported_name.shouldnt_be_none()
        exported_name.should_be_a(bytes)
        exported_name.shouldnt_be_empty()

    def test_duplicate_name(self):
        orig_name = gb.importName(TARGET_SERVICE_NAME)
        new_name = gb.duplicateName(orig_name)

        new_name.shouldnt_be_none()
        gb.compareName(orig_name, new_name).should_be_true()

    def test_display_name(self):
        imported_name = gb.importName(TARGET_SERVICE_NAME)
        displ_resp = gb.displayName(imported_name)

        displ_resp.shouldnt_be_none()

        (displayed_name, out_type) = displ_resp

        displayed_name.shouldnt_be_none()
        displayed_name.should_be_a(bytes)
        displayed_name.should_be(TARGET_SERVICE_NAME)

        out_type.shouldnt_be_none()
        out_type.should_be(gb.NameType.hostbased_service)

    def test_compare_name(self):
        service_name1 = gb.importName(TARGET_SERVICE_NAME)
        service_name2 = gb.importName(TARGET_SERVICE_NAME)
        init_name = gb.importName(INITIATOR_PRINCIPAL, gb.NameType.principal)

        gb.compareName(service_name1, service_name2).should_be_true()
        gb.compareName(service_name2, service_name1).should_be_true()

        gb.compareName(service_name1, init_name).should_be_false()

        gb.releaseName(service_name1)
        gb.releaseName(service_name2)
        gb.releaseName(init_name)

    def test_display_status(self):
        status_resp = gb.displayStatus(0, False)
        status_resp.shouldnt_be_none()

        (status, ctx, cont) = status_resp

        status.should_be_a(bytes)
        status.shouldnt_be_empty()

        ctx.should_be_a(int)

        cont.should_be_a(bool)
        cont.should_be_false()

    def test_acquire_creds(self):
        name = gb.importName((TARGET_SERVICE_NAME + b'/' +
                              socket.getfqdn().encode('utf-8')),
                             gb.NameType.principal)
        cred_resp = gb.acquireCred(name)
        cred_resp.shouldnt_be_none()

        (creds, actual_mechs, ttl) = cred_resp

        creds.shouldnt_be_none()
        creds.should_be_a(gb.Creds)

        actual_mechs.shouldnt_be_empty()
        actual_mechs.should_include(gb.MechType.kerberos)

        ttl.should_be_a(int)

        gb.releaseName(name)
        gb.releaseCred(creds)

    def test_context_time(self):
        target_name = gb.importName(TARGET_SERVICE_NAME)
        ctx_resp = gb.initSecContext(target_name)

        client_token1 = ctx_resp[3]
        client_ctx = ctx_resp[0]
        str_server_name = (TARGET_SERVICE_NAME + b'/' +
                           socket.getfqdn().encode('utf-8'))
        server_name = gb.importName(str_server_name,
                                    gb.NameType.principal)
        server_creds = gb.acquireCred(server_name)[0]
        server_resp = gb.acceptSecContext(client_token1,
                                          acceptor_cred=server_creds)
        server_tok = server_resp[3]

        client_resp2 = gb.initSecContext(target_name,
                                         context=client_ctx,
                                         input_token=server_tok)
        ctx = client_resp2[0]

        ttl = gb.contextTime(ctx)

        ttl.should_be_a(int)
        ttl.should_be_greater_than(0)

    def test_inquire_context(self):
        target_name = gb.importName(TARGET_SERVICE_NAME)
        ctx_resp = gb.initSecContext(target_name)

        client_token1 = ctx_resp[3]
        client_ctx = ctx_resp[0]
        str_server_name = (TARGET_SERVICE_NAME + b'/' +
                           socket.getfqdn().encode('utf-8'))
        server_name = gb.importName(str_server_name,
                                    gb.NameType.principal)
        server_creds = gb.acquireCred(server_name)[0]
        server_resp = gb.acceptSecContext(client_token1,
                                          acceptor_cred=server_creds)
        server_tok = server_resp[3]

        client_resp2 = gb.initSecContext(target_name,
                                         context=client_ctx,
                                         input_token=server_tok)
        ctx = client_resp2[0]

        inq_resp = gb.inquireContext(ctx)
        inq_resp.shouldnt_be_none()

        (src_name, target_name, ttl, mech_type,
         flags, local_est, is_open) = inq_resp

        src_name.shouldnt_be_none()
        src_name.should_be_a(gb.Name)

        target_name.shouldnt_be_none()
        target_name.should_be_a(gb.Name)

        ttl.should_be_a(int)

        mech_type.shouldnt_be_none()
        mech_type.should_be(gb.MechType.kerberos)

        flags.shouldnt_be_none()
        flags.should_be_a(list)
        flags.shouldnt_be_empty()

        local_est.should_be_a(bool)
        local_est.should_be_true()

        is_open.should_be_a(bool)
        is_open.should_be_true()


class TestInitContext(unittest.TestCase):
    def setUp(self):
        self.target_name = gb.importName(TARGET_SERVICE_NAME)

    def tearDown(self):
        gb.releaseName(self.target_name)

    def test_basic_init_default_ctx(self):
        ctx_resp = gb.initSecContext(self.target_name)
        ctx_resp.shouldnt_be_none()

        (ctx, out_mech_type,
         out_req_flags, out_token, out_ttl, cont_needed) = ctx_resp

        ctx.shouldnt_be_none()
        ctx.should_be_a(gb.SecurityContext)

        out_mech_type.should_be(gb.MechType.kerberos)

        out_req_flags.should_be_a(list)
        out_req_flags.should_be_at_least_length(2)

        out_token.shouldnt_be_empty()

        out_ttl.should_be_greater_than(0)

        cont_needed.should_be_a(bool)

        gb.deleteSecContext(ctx)


class TestAcceptContext(unittest.TestCase):

    def setUp(self):
        self.target_name = gb.importName(TARGET_SERVICE_NAME)
        ctx_resp = gb.initSecContext(self.target_name)

        self.client_token = ctx_resp[3]
        self.client_ctx = ctx_resp[0]
        self.client_ctx.shouldnt_be_none()

        str_server_name = (TARGET_SERVICE_NAME + b'/' +
                           socket.getfqdn().encode('utf-8'))
        self.server_name = gb.importName(str_server_name,
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
        self.server_ctx.should_be_a(gb.SecurityContext)

        name.shouldnt_be_none()
        name.should_be_a(gb.Name)

        mech_type.should_be(gb.MechType.kerberos)

        out_token.shouldnt_be_empty()

        out_req_flags.should_be_a(list)
        out_req_flags.should_be_at_least_length(2)

        out_ttl.should_be_greater_than(0)

        if delegated_cred is not None:
            delegated_cred.should_be_a(gb.Creds)

        cont_needed.should_be_a(bool)


class TestWrapUnwrap(unittest.TestCase):
    def setUp(self):
        self.target_name = gb.importName(TARGET_SERVICE_NAME)
        ctx_resp = gb.initSecContext(self.target_name)

        self.client_token1 = ctx_resp[3]
        self.client_ctx = ctx_resp[0]
        str_server_name = (TARGET_SERVICE_NAME + b'/' +
                           socket.getfqdn().encode('utf-8'))
        self.server_name = gb.importName(str_server_name,
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

    def test_get_mic(self):
        mic_token = gb.getMIC(self.client_ctx, b"some message")

        mic_token.shouldnt_be_none()
        mic_token.should_be_a(bytes)
        mic_token.shouldnt_be_empty()

    def test_basic_verify_mic(self):
        mic_token = gb.getMIC(self.client_ctx, b"some message")

        qop_used = gb.verifyMIC(self.server_ctx, b"some message", mic_token)

        qop_used.should_be_a(int)

        # test a bad MIC
        gb.verifyMIC.should_raise(gb.GSSError, self.server_ctx,
                                  b"some other message", b"some invalid mic")

    def test_bool_verify_mic(self):
        mic_token = gb.getMIC(self.client_ctx, b"some message")

        (was_valid, qop_used, majs, mins) = gb.verifyMIC(self.server_ctx,
                                                         b"some message",
                                                         mic_token,
                                                         True)

        was_valid.should_be_true()
        qop_used.should_be_a(int)
        majs.should_be_a(int)
        mins.should_be_a(int)

        (was_valid2, qop_used, majs, mins) = gb.verifyMIC(self.server_ctx,
                                                          b"some new message",
                                                          b"some invalid mic",
                                                          True)

        was_valid2.should_be_false()
        qop_used.should_be_a(int)
        majs.should_be_a(int)
        mins.should_be_a(int)

    def test_wrap_size_limit(self):
        with_conf = gb.wrapSizeLimit(self.client_ctx, 100)
        without_conf = gb.wrapSizeLimit(self.client_ctx, 100,
                                        confidential=False)

        with_conf.should_be_a(int)
        without_conf.should_be_a(int)

        without_conf.should_be_less_than(100)
        with_conf.should_be_less_than(100)

    def test_basic_wrap_unwrap(self):
        (wrapped_message, conf) = gb.wrap(self.client_ctx, b'test message')

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

        unwrapped_message.should_be_a(bytes)
        unwrapped_message.shouldnt_be_empty()
        unwrapped_message.should_be(b'test message')
