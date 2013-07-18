from __future__ import print_function
import gssapi.base as gss
import struct
import sys
from gssapi.type_wrappers import GSSName


def debug(p, v):
    print("{0}: {1}".format(p.upper(), v), file=sys.stderr)


class GSSClientError(Exception):
    """
    GSS Client Error

    This Exception represents an error which occured
    when executing the GSS Client code (as opposed to
    :class:`gssapi.base.types.GSSError`, which are errors
    which occured directly in the GSSAPI C code).
    """
    pass


class BasicGSSClient(object):
    """
    Basic GSS Client

    This class implements all functionality needed to initialize a basic
    GSS connection and send/receive encrypted or signed messages.

    :param str principal: the service principal to which to connect
                          (automatically converted to a
                          :class:`gssapi.type_wrappers.GSSName`)
    :param dbg: a method for printing debug messages (not currently used)
    :type dbg: function(title, message)
    :param security_type: the level of security to use
    :type security_type: str containing enc(crypted)/conf(idential),
                         integ(rity) or any, or just None
    :param max_msg_size: the maximum message size for encryption/decryption
    :type max_msg_size: int > 0 or None (for default)

    .. warning::

       All methods in this class can potentially raise
       :class:`gssapi.base.types.GSSError`

    .. attribute:: service_principal

       The service principal to which we are connecting
       (as a :class:`gssapi.type_wrappers.GSSName`)

    .. attribute:: ctx

       Type: Capsule

       The internal GSS context object

    .. attribute:: token

       Type: bytes

       The last returned token from one of the token-manipulation methods

    .. attribute:: ttl

       Type: int >= 0

       The desired time-to-live for the GSS context object

    .. attribute:: last_ttl

       Type: int > 0

       The actual amount of time for which the current
       GSS context object will be valid

    .. attribute:: qop

       Type: int > 0 or None

       The current Quality of Protection being used in the
       encryption/decryption process (set this to the desired QoP, or
       None for default, to attempt to use that QoP)

    .. attribute:: services

       Type: [:class:`gssapi.base.types.RequirementFlag`]

       The flags to use when creating the GSS context

    .. attribute:: channel_bindings

       Type: TBD or None

       .. warning::

          Not Currently Implemented

    .. attribute:: mech_type

       Type: Capsule or None

       Represents the desired mechanism type to be used
       (None uses the default type).

       .. seealso::

          Function :func:`resolveMechType`
    """

    def __init__(self, principal,
                 security_type='encrypted', max_msg_size=None):

        self.service_principal = GSSName(principal)
        self.ctx = None
        self.token = None
        self.ttl = 0
        self.last_ttl = None
        self.channel_bindings = None
        self.mech_type = None
        self.services = [gss.RequirementFlag.mutual_authentication,
                         gss.RequirementFlag.out_of_sequence_detection]

        if security_type[0:5] == 'integ':
            self.security_type = gss.RequirementFlag.integrity
            self.services.append(self.security_type)
        elif security_type[0:4] == 'conf' or security_type[0:3] == 'enc':
            self.security_type = gss.RequirementFlag.confidentiality
            self.services.append(self.security_type)
            self.services.append(gss.RequirementFlag.integrity)
        elif security_type == 'any':
            self.security_type = None
        else:
            self.security_type = 0

    def resolveMechType(self, mt):
        """
        Sets the current mechanims type

        This method converts a :class:`gssapi.base.types.MechanismType` into
        a capsule object usable by internal methods, and then sets
        :attr:`mech_type` to the resulting capsule

        :param mt: the desired mechanism type
        :type mt: :class:`gssapi.base.types.MechanismType`
        """

        self.mech_type = gss.getMechanismType(mt)

    def createDefaultToken(self):
        """
        Initializes a default token and security context

        This method gets and returns a default token, and
        initializes the corresponding security context

        :rtype: bytes
        :returns: the token created in the process of
                  initializing the security context
        """

        resp = gss.initSecContext(self.service_principal.capsule,
                                  services=self.services,
                                  channel_bindings=self.channel_bindings,
                                  mech_type=self.mech_type,
                                  time=self.ttl)

        (self.ctx, _, _, self.token, self.last_ttl, _) = resp
        return self.token

    def processServerToken(self, server_tok):
        """
        Processes a server token, and updates the security context

        This method processes a server token, updates the internal
        security context, and returns the new resulting token.

        :param bytes server_tok: the token sent from the server
        :rtype: bytes
        :returns: the token resulting from updating the security context
        """

        resp = gss.initSecContext(self.service_principal.capsule,
                                  context=self.ctx,
                                  input_token=server_tok,
                                  services=self.services,
                                  channel_bindings=self.channel_bindings,
                                  mech_type=self.mech_type,
                                  time=self.ttl)

        (self.ctx, _, _, self.token, self.last_ttl, _) = resp
        return self.token

    def encrypt(self, msg):
        """
        Encrypts a message

        This method encrypts a message according to the current
        QoP (:attr:`qop`) and security level

        :param str msg: the message to be encrypted
        :rtype: bytes
        :returns: the encrypted form of the message
        :except GSSClientError: if the requested security level
                                could not be used
        """

        if self.security_type == gss.RequirementFlag.integrity:
            return gss.wrap(self.ctx, msg, False, None)[0]
        elif self.security_type == gss.RequirementFlag.confidentiality:
            res, used = gss.wrap(self.ctx, msg, True, None)
            if not used:
                raise GSSClientError('User requested encryption, '
                                     'but it was not used!')
            return res
        else:
            return msg

    def decrypt(self, msg):
        """
        Decrypts a message

        This method decrypts a message encrypted by the server.

        :param bytes msg: the message to be decrypted
        :rtype: str
        :returns: the decrypted message
        :except GSSClientError: if encryption was requested but not used,
                or if the QoP failed to meet our standards
        """

        if self.security_type is not None and self.security_type != 0:
            res, used, qop = gss.unwrap(self.ctx, msg)
            isconf = self.security_type == gss.RequirementFlag.confidentiality
            if (not used and isconf):
                raise GSSClientError('User requested encryption, '
                                     'but the server sent an unencrypted '
                                     'message!')
            return res
        else:
            return msg

    def __del__(self):
        if self.ctx is not None:
            gss.deleteSecContext(self.ctx)


class SASLGSSClientError(GSSClientError):
    """
    SASL GSS Client Error

    This Exception represents an error which occured
    when executing the SASL GSS Client helper code (as opposed to
    :class:`gssapi.base.types.GSSError`, which are errors which
    occured directly in the GSSAPI C code).
    """
    pass


class BasicSASLGSSClient(BasicGSSClient):
    """
    A helper for using the SASL GSSAPI mechanism

    This class contains helper code to support implementing
    the SASL GSSAPI mechanism using PyGSSAPI.

    All parameters besides username are used as in :class:`BasicGSSClient`.
    All relevant attributes are set according to the SASL GSSAPI RFC
    (http://tools.ietf.org/html/rfc4752).

    :param str username: the user principal with which to authenticate

    .. attribute:: user_principal

       The username to use in the authentication process

       .. warning::

          Unlike :attr:`service_principal`, this is just a string,
          not a :class:`gssapi.type_wrappers.GSSName`
    """

    def __init__(self, username, service_principal,
                 max_msg_size=None, *args, **kwargs):

        self.user_principal = username
        self.max_msg_size = max_msg_size
        super(BasicSASLGSSClient, self).__init__(service_principal,
                                                 *args, **kwargs)

        self.channel_bindings = None
        self.resolveMechType(gss.MechType.kerberos)

        if (self.services is None):
            self.services = []

        if (self.security_type == gss.RequirementFlag.confidentiality):
            self.services.append(self.security_type)

        self.services.append(gss.RequirementFlag.integrity)

        if (self.security_type != 0):
            base_flags = [gss.RequirementFlag.mutual_authentication,
                          gss.RequirementFlag.out_of_sequence_detection]
            self.services.extend(base_flags)

        self.INV_SEC_LAYER_MASKS = {v: k
                                    for k, v
                                    in self.SEC_LAYER_MASKS.items()}

    def step1(self):
        """
        Creates a default token

        This method is step 1 in the SASL process, and
        creates a default token

        :rtype: bytes
        :returns: a default token to send to the server
        """
        return self.createDefaultToken()

    def step2(self, server_tok):
        """
        Processes a server token

        This method is step 2 in the SASL process, and
        processes a server token

        :param bytes server_tok: the token returned from the server
        :rtype: bytes
        :returns: a token or empty string to be sent to the server
        """
        return self.processServerToken(server_tok)

    SEC_LAYER_MASKS = {
        0: 1,
        gss.RequirementFlag.integrity: 2,
        gss.RequirementFlag.confidentiality: 4
    }

    INV_SEC_LAYER_MASKS = None

    def step3(self, tok):
        """
        Deals with SSF

        This method deals with negotiating SSF (the security level)
        and max message size, setting the max message size appropriately

        :param bytes tok: the wrapped message sent from the server
        :rtype: bytes
        :returns: a wrapped message to be sent to the server declaring
                  our security level and max message size
        """

        # we don't care out security for this,
        # so we don't use self.unwrap
        unwrapped_tok = gss.unwrap(self.ctx, tok)[0]
        sec_layers_supported_raw = ord(unwrapped_tok[0])
        max_server_msg_size_raw = '\x00' + unwrapped_tok[1:4]
        max_server_msg_size = struct.unpack('!L', max_server_msg_size_raw)[0]

        if (self.max_msg_size is None
                or self.max_msg_size > max_server_msg_size):

            self.max_msg_size = max_server_msg_size

        sec_layers_supported = []
        for name, mask in self.SEC_LAYER_MASKS.items():
            if sec_layers_supported_raw & mask > 0:
                sec_layers_supported.append(name)

        sec_layer_choice = 0
        if self.security_type == 'any':
            for mask in self.SEC_LAYER_MASKS.values():
                if mask & sec_layers_supported_raw > sec_layer_choice:
                    sec_layer_choice = mask
        elif self.security_type in sec_layers_supported:
            sec_layer_choice = self.SEC_LAYER_MASKS[self.security_type]
        else:
            raise SASLGSSClientError('Server is unable to accomodate '
                                     'our security level!')

        if self.security_layer is None:
            self.security_layer = self.INV_SEC_LAYER_MASKS[sec_layer_choice]

        resp = (chr(sec_layer_choice) +
                struct.pack('!L', self.max_msg_size)[0:3] +
                self.user_principal)

        # again, we don't care about our selected security type for this one
        return gss.wrap(self.ctx, resp, False, None)[0]
