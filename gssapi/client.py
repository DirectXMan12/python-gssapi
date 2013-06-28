from __future__ import print_function
import gssapi.base as gss
import struct
import sys
from gssapi.type_wrappers import GSSName

def debug(p, v):
    print("{0}: {1}".format(p.upper(), v), file=sys.stderr)

class GSSClientError(object):
    pass

class BasicGSSClient(object):
    def __init__(self, principal, dbg=debug, security_type='encrypted', max_msg_size=None):
        self.debug = dbg
        self.service_principal = GSSName(principal)
        self.ctx = None
        self.initial_token = None
        self.ttl = 0
        self.qop = None
        self.flags = None
        self.channel_bindings = None
        self.mech_type = None
        self.services = None

        if security_type[0:5] == 'integ':
            self.security_type = gss.RequirementFlag.integrity
        elif security_type[0:4] == 'conf' or security_type[0:3] == 'enc':
            self.security_type = gss.RequirementFlag.confidentiality
        elif security_type == 'any':
            self.security_type = None
        else:
            self.security_type = 0

    def resolveMechType(self, mt):
        self.mech_type = gss.getMechanismType(mt)

    def createDefaultToken(self):
       self.ctx, _, _, self.token, self.ttl, _ = gss.initSecContext(self.service_principal.capsule,
                                                                    services=self.flags,
                                                                    channel_bindings=self.channel_bindings,
                                                                    mech_type=self.mech_type,
                                                                    time=self.ttl)
       return self.token

    def processServerToken(self, server_tok):
       self.ctx, _, _, self.token, self.ttl, _ = gss.initSecContext(self.service_principal.capsule,
                                                                    context=self.ctx,
                                                                    input_token=server_tok,
                                                                    services=self.flags,
                                                                    channel_bindings=self.channel_bindings,
                                                                    mech_type=self.mech_type,
                                                                    time=self.ttl)
       return self.token
    
    def encrypt(self, msg):
        if self.security_type == gss.RequirementFlag.integrity:
            gss.wrap(self.ctx, msg, False, self.qop)[0]
        elif self.security_type == gss.RequirementFlag.confidentiality:
            res, used = gss.wrap(self.ctx, msg, True, self.qop)
            if not used:
                raise GSSClientError('User requested encryption, but it was not used!')
            return res
        else:
            return msg
    
    def decrypt(self, msg):
        if self.security_type is not None and self.security_type != 0:
            res, used, qop = gss.unwrap(self.ctx, msg)
            if not used and self.security_type == gss.RequirementFlag.confidentiality:
                raise GSSClientError('User requested encryption, but the server sent an unencrypted message!')

            if self.qop is None:
                self.qop = qop
            elif qop < self.qop:
                raise GSSClientError('Server used a lower quality of protection than we expected!')

            return res
        else:
            return msg

    def __del__(self):
        if self.ctx is not None:
            gss.deleteSecContext(self.ctx)

class SASLGSSClientError(GSSClientError):
    pass

class BasicSASLGSSClient(BasicGSSClient):
    def __init__(self, username, service_principal, max_msg_size=None, *args, **kwargs):
        self.user_principal = username
        self.max_msg_size = max_msg_size
        super(BasicSASLGSSClient, self).__init__(service_principal, *args, **kwargs)

        self.channel_bindings = None
        self.resolveMechType(gss.MechType.kerberos)
        
        if (self.services is None):
            self.services = []

        if (self.security_type == gss.RequirementFlag.confidentiality):
            self.services.append(self.security_type)
        
        self.services.append(gss.RequirementFlag.integrity)

        if (self.security_type != 0):
            self.services.extend([gss.RequirementFlag.mutual_authentication,
                                  gss.RequirementFlag.out_of_sequence_detection])

        self.INV_SEC_LAYER_MASKS = {v:k for k, v in self.SEC_LAYER_MASKS.items()}
    
    def step1(self):
        return self.createDefaultToken()

    def step2(self, server_tok):
        return self.processServerToken(server_tok) 

    SEC_LAYER_MASKS = {
        0: 1,
        gss.RequirementFlag.integrity: 2,
        gss.RequirementFlag.confidentiality: 4
    }

    INV_SEC_LAYER_MASKS = None

    def step3(self, tok):
        unwrapped_tok = gss.unwrap(self.ctx, msg)[0] # we don't care out security for this
        sec_layers_supported_raw = ord(unwrapped_tok[0])
        max_server_msg_size_raw = '\x00' + unwrapped_tok[1:4]
        max_server_msg_size = struct.unpack('!L', max_server_msg_size_raw)[0]

        if self.max_msg_size is None or self.max_msg_size > max_server_msg_size:
            self.max_msg_size = max_server_msg_size
            
        sec_layers_supported = []
        for name, mask in self.SEC_LAYER_MASKS.items():
            if sec_layers_supported_raw & mask > 0:
                sec_layers_supported.append(name)

        sec_layer_choice = 0
        if self.security_type is None: # None means any
            for mask in self.SEC_LAYER_MASKS.values():
                if mask & sec_layers_supported_raw > sec_layer_choice:
                    sec_layer_choice = mask
        elif self.security_type in sec_layers_supported:
            sec_layer_choice = self.SEC_LAYER_MASKS[self.security_type]
        else:
            raise SASLGSSClientError('Server is unable to accomodate our security level!')

        if self.security_layer is None:
            self.security_layer = INV_SEC_LAYER_MASKS[sec_layer_choice]
            
        
        resp = chr(sec_layer_choice) + struct.pack('!L', self.max_msg_size)[0:3] + self.user_principal
        return gss.wrap(self.ctx, resp, False, self.qop)[0] # again, we don't care about our selected security type for this one
