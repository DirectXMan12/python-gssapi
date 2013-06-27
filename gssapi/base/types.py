from flufl.enum import Enum
from flufl.enum import IntEnum
from gssapi.base.ctypes import *

class NameType(IntEnum):
#   hostbased_service = GSS_C_NT_HOSTBASED_SERVICE 
#   principal = GSS_C_NT_PRINCIPAL_NAME
#   user = GSS_C_NT_USER_NAME
#   anonymous = GSS_C_NT_ANONYMOUS
#   machine_uid = GSS_C_NT_MACHINE_UID_NAME
#   string_uid = GSS_C_NT_STRING_UID_NAME
#   export = GSS_C_NT_EXPORT_NAME
    hostbased_service = 0
    principal = 1
    user = 2
    anonymous = 3
    machine_uid = 4
    string_uid = 5
    export = 6
    # NOTE: there are more kerberos specific names, but I think
    #       those are just hold-overs from before the GSS_C_NT_
    #       names were there (check gss_krb5_nt_)

class RequirementFlag(IntEnum):
    delegate_to_peer = GSS_C_DELEG_FLAG
    mutual_authentication = GSS_C_MUTUAL_FLAG
    replay_detection = GSS_C_REPLAY_FLAG
    out_of_sequence_detection = GSS_C_SEQUENCE_FLAG
    confidentiality = GSS_C_CONF_FLAG
    integrity = GSS_C_INTEG_FLAG
    anonymous = GSS_C_ANON_FLAG
    transferable = GSS_C_TRANS_FLAG

class KerberosError(Exception):
    pass

# TODO(ross): make an error for each error return code
class GSSError(KerberosError):
    pass
