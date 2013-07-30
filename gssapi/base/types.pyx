STUFF = "Hi"

from flufl.enum import IntEnum
from gssapi.base.cython_types cimport *

class NameType(IntEnum):
    """
    GSSAPI Name Types

    This IntEnum represents GSSAPI name types
    (to be used with importName, etc)

    Note that the integers behind these
    enum members do not correspond to any numbers
    in the GSSAPI C bindings, and are subject
    to change at any point.
    """

    #  hostbased_service = GSS_C_NT_HOSTBASED_SERVICE
    #  principal = GSS_KRB5_NT_PRINCIPAL_NAME
    #  user = GSS_C_NT_USER_NAME
    #  anonymous = GSS_C_NT_ANONYMOUS
    #  machine_uid = GSS_C_NT_MACHINE_UID_NAME
    #  string_uid = GSS_C_NT_STRING_UID_NAME
    #  export = GSS_C_NT_EXPORT_NAME
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
    """
    GSSAPI Requirement Flags

    This IntEnum represents flags to be used in the
    service flags parameter of initSecContext.

    The numbers behind the values correspond directly
    to their C counterparts.
    """

    delegate_to_peer = GSS_C_DELEG_FLAG
    mutual_authentication = GSS_C_MUTUAL_FLAG
    replay_detection = GSS_C_REPLAY_FLAG
    out_of_sequence_detection = GSS_C_SEQUENCE_FLAG
    confidentiality = GSS_C_CONF_FLAG
    integrity = GSS_C_INTEG_FLAG
    anonymous = GSS_C_ANON_FLAG
    transferable = GSS_C_TRANS_FLAG


class MechType(IntEnum):
    """
    GSSAPI Mechanism Types

    This IntEnum represents explicit GSSAPI mechanism types
    (to be used with initSecContext).

    Note that the integers behind these enum members do not
    correspond to any numbers in the GSSAPI C bindings, and are
    subject oto change at any point.
    """

    kerberos = 0
