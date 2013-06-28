def displayStatus(err_code, is_major_code, mech_type=None, message_context=0):
    """
    Convert a GSSAPI status code into a human-readable string

    Converts the given general GSSAPI (major) status code or
    mechanism-specific (minor) status code into a human-readable
    string.  This method may need to be called multiple times,
    which is what the message_context parameter is for.

    :param int err_code: the status code in question
    :param bool is_major_code: is this a general GSS status code (True)
                               or a mechanism-specific status code (False)
    :param mech_type: the OID of the mechanism type, or None for
                      a default value (currently only this is supported)
    :param int message_context: the "context" for this call of displayStatus,
                                returned from previous calls to displayStatus
    :rtype: (str, int, bool)
    :returns: a tuple containing the result message, the message context for
              any further calls, and whether or not further calls can be made
    """
