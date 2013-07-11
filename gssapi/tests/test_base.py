import unittest
import should_be.all
import gssapi.base as gb


class TestBaseUtilities(unittest.TestCase):
    def test_import_name(self):
        imported_name = gb.importName('vnc')

        imported_name.shouldnt_be_none()
        imported_name.should_be_a('PyCapsule')

        releaseName(imported_name)

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

class TestBaseCore(unittest.TestCase):
    def setUp(self):
        self.target_name = gb.importName('vnc')
        self.target_name.shouldnt_be_none()

    def test_init_default_ctx(self):
        ctx_resp = gb.initSecContext(self.target_name)
        ctx_resp.shouldnt_be_none()

        (ctx, out_mech_type, out_req_flags, out_token, out_ttl, cont_needed) = ctx_resp

        ctx.shouldnt_be_none()
        ctx.should_be_a('PyCapsule')

        out_mech_type.shouldnt_be_none()
        out_mech_type.should_be(gb.MechType.kerberos)

        out_req_flags.should_be_a(list)
        out_req_flags.should_have_length(2)

        out_token.shouldnt_be_empty()

        out_ttl.should_be_greater_than(0)

        cont_needed.should_be_a(bool)

    def test_wrap_conf(self):
        ctx_resp = gb.initSecContext(self.target_name)
        ctx_resp.shouldnt_be_none()

        ctx = ctx_resp[0]
        ctx.shouldnt_be_none(0)

        wrapped_message = gb.wrap(ctx, 'test message')

        wrapped_message.should_be_a(str)
        wrapped_message.shouldnt_be_empty()
        wrapped_message.should_be_longer_than('test message')
