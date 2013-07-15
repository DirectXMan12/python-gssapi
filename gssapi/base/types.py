from flufl.enum import IntEnum
from gssapi.base.ctypes import *  # noqa
from gssapi.base.status_utils import displayStatus


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
    #  principal = GSS_C_NT_PRINCIPAL_NAME
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


# TODO(ross): make an error for each error return code?
class GSSError(Exception):
    """
    GSSAPI Error

    This Exception represents an error returned from the GSSAPI
    C bindings.  It contains the major and minor status codes
    returned by the method which caused the error, and can
    generate human-readable string messages from the error
    codes
    """

    def __init__(self, maj_code, min_code):
        """
        Creates a new GSSError

        This method creates a new GSSError,
        retrieves the releated human-readable
        string messages, and uses the results to construct an
        exception message

        :param int maj_code: the major code associated with this error
        :param int min_code: the minor code associated with this error
        """

        self.maj_code = maj_code
        self.min_code = min_code

        super(GSSError, self).__init__(self.gen_message())

    def get_all_statuses(self, code, is_maj):
        """
        Retrieves all messages for a status code

        This method retrieves all human-readable messages
        available for the given status code.

        :param int code: the status code in question
        :param bool is_maj: whether this is a major status code (True)
                            or minor status code (False)
        :rtype: [str]
        :returns: a list of string messages for this error code
        """

        res = []
        last_str, last_ctx, cont = displayStatus(code, is_maj)
        res.append(last_str)
        while cont:
            last_str, last_ctx, cont = displayStatus(code, is_maj,
                                                     message_context=last_ctx)
            res.append(last_str)

        return res

    def gen_message(self):
        """
        Retrieves all messages for this error's status codes

        This method retrieves all messages for this error's status codes,
        and forms them into a string for use as an exception message

        :rtype: str
        :returns: a string for use as this error's message
        """

        maj_statuses = self.get_all_statuses(self.maj_code, True)
        min_statuses = self.get_all_statuses(self.min_code, False)

        msg = "Major ({maj_stat}): {maj_str}, Minor ({min_stat}): {min_str}"
        return msg.format(maj_stat=self.maj_code,
                          maj_str=maj_statuses,
                          min_stat=self.min_code,
                          min_str=min_statuses)
