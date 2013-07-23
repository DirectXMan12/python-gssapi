from gssapi.base.types import NameType


def indicateMechs():
    """
    Gets the Currently Supported GSS Mechanisms

    This method gets a list of the GSS mechanisms
    supported by the current GSSAPI implementation

    :returns: the supported mechanisms
    :rtype: [:class:`gssapi.base.types.MechType`]
    :except GSSError:
    """


def importName(name, name_type=NameType.hostbased_service):
    """
    Gets a GSSAPI Name

    This method converts a string name and type into a 'name'
    string usable in future calls to GSSAPI.

    NOTE: This name needs to have its name released when finished

    :param str name: the plain 'name' to obtain
    :param name_type: the type of the name we are passing in
    :type name_type: :class:`NameType`
    :rtype: bytes
    :returns: the GSSAPI name string for use in other GSSAPI methods
    :except GSSError:
    """


def displayName(name):
    """
    Converts a GSSAPI Name into a String

    This function is essentially the opposite of :func:`importName`:
    it takes a GSSAPI name and converts it back into a string and
    name type.

    :param name: a GSSAPI name capsule
    :returns: a tuple containing the string-version of the name
              and its name type
    :rtype: (bytes, :class:`gssapi.base.types.NameType`)
    :except GSSError:
    """


def compareName(name1, name2):
    """
    Compares Two GSSAPI Names

    This method compares to GSSAPI names to see if they are
    equal.

    :param name1: the first name to compare
    :param name2: the second name to compare
    :returns: whether or not the two names are equal
    :rtype: bool
    """


def releaseName(name_obj):
    """
    Releases a GSSAPI Name

    This method releases a GSSAPI name that was allocated with importName

    :param name_obj: the name object to be released
    :returns: None
    """


def acquireCred(name, ttl=0, mechs=None, cred_usage=None):
    """
    Acquires GSSAPI Credentials

    This method acquires credentials for the given
    name (imported with :func:`importName`) for the desired
    mechanims, with permissions to either initiate security
    contexts, accept them, or both.

    :param name: the name object for which to get credentials
    :param int input_ttl: the requested TTL for these credentials
    :param mechs: the mechanims types with which these credentials
                  are to be used, or None for the default set
    :type mechs: [:class:`gssapi.base.types.MechType`] or None
    :param cred_usage: How these credentials are going to be used:
                       To accept a context (True), to initiate a
                       context (False), or both (None)
    :type cred_usage: bool or None
    :returns: a tuple containing the actual credentials, the mechanisms
              for which these credentials are valid, and the actual TTL
              (which may be 0)
              (i.e. (creds, [MechType], ttl))
    """


def releaseCred(cred_obj):
    """
    Releases GSSAPI credentials

    This method releases GSSAPI credentials that were
    allocated with acquireCred

    :param cred_obj: the name credentials object to be released
    :returns: None
    """


def deleteSecContext(context, output_needed=False):
    """
    Releases a security context

    This method releases a security context, potentially providing an
    output buffer as the result

    :param context: the context to be released
    :param bool output_needed: is an output_buffer desired?
    :rtype: bytes or None
    :returns: an output token, if requested (otherwise None)
    """


# TODO(sross): add support for channel bindings
def initSecContext(target_name, cred=None, context=None, mech_type=None,
                   flags=None, time=0, channel_bindings=None,
                   input_token=None):
    """
    Initializes a GSS Security Context

    (Client)
    This method initializes a GSSAPI security context
    with the given parameters.  The default flags for
    the flags field are MUTUAL and SEQUENCE.

    :param target_name: the name of the target
                        (commonly the server name, retrieved using importName)
    :param cred: The handle for credentials claimed
                 (returned from acquireCred),
                 or None to use the default initiator principal
    :param context: The current context, or None if this is the first call
    :param mech_type: the mechanism type
                      (None for default, otherwise a capsule
                      from :func:`getMechanismType`)
    :param flags: the requested flags
    :type flags: [:class:`RequirementFlag`]
    :param int time: the requested TTL for this context
                     (0 uses the default TTL)
    :param channel_bindings: the requested input channel bindings
                             (currently only None is supported)
    :param bytes input_token: the input token (use None for the first call)
    :returns: a tuple containing
              the (potentially modified) context,
              the actual mechanism type used,
              the output token,
              the actual flags provided,
              the actual TTL for this context,
              and whether or not a continue is needed
              (i.e. (context, MechType, [RequirementFlag],
                     bytes, TTL, continue_needed))
    :except GSSError:
    """


def acceptSecContext(input_token, acceptor_cred=None,
                     ctx=None, channel_bindings=None):
    """
    Accepts a GSS Security Context

    (Server)
    This method accepts a GSSAPI security context
    based on the given parameters, including the token
    sent by the client returned from :func:`initSecContext`

    :param str input_token: the token sent from the client
    :param acceptor_cred: the handle for the credentials (returned from
                          acquireCred) used to accept the context, or None
                          to use the default acceptor principal
    :param ctx: the current context, or None for a new context
    :param channel_bindings: the requested channel bindings
                             (currently on None is accepted)
    :returns: a tuple containing
              the (potentially modified) context,
              the authenticated name of the context initiator,
              the mechanism type used,
              the output token (to send to the client),
              the flags in use,
              the TTL for the context,
              and the delegated credential handle
                (or None if
                 RequirementFlags.delegate_to_peer is not present
                 in the flags)
              (i.e. (context, name, MechType, bytes,
                     [RequirementFlag], int, delegated_cred, continue_needed))
    :except GSSError:
    """


def getMechanismType(mech_type):
    """
    Converts a value from the MechType enum into a gss_OID

    This method converts a value from the MechType enum into a gss_OID,
    which can be used in GSSAPI methods such as initSecContext

    :param MechType mech_type: the mechanism type
    :returns: a gss_OID capsule representing the selected mechanism type
    """


def getMIC(ctx, message, qop=None):
    """
    Generates a MIC for a Message

    This method generates a cryptographic message integrity code
    for the supplied method.  The QoP can be changed to vary the
    algorithm used.  The output is a token that can be transfered
    to a peer application.

    :param ctx: the current security context
    :param bytes message: the message for which the MIC is to be generated
    :param qop: the quality of protection (used to change which algorithm
                is used) (supply None for default)
    :type qop: int or None
    :returns: the MIC encoded into a token
    :rtype: bytes
    :except GSSError:
    """


def verifyMIC(ctx, message, token, return_bool=False):
    """
    Verifies a Message's MIC

    This method verifies that the message matches the given message integrity
    code (token).

    .. note::

       This method does not throw an error on GSS_S_DUPLICATE_TOKEN,
       which simply indicates that the token was valid and contained
       the correct MIC for the message, but had already be processed.
       Instead, it simply returns that the MIC was valid, since this
       is not really an error.

    :param ctx: the current security context
    :param bytes message: the message in question
    :param bytes token: the MIC token for the message in question
    :param bool return_bool: see return value explanation
    :returns: this depends on the value of :param:`return_bool`.
              If False, the QoP used to generate the MIC is returned
              if the verification is successfull, and and error is raised
              otherwise.
              If True, a tuple is returned containing whether or not the
              MIC was valid, the QoP used, the major result code, and the
              minor result code (which can be interpreted with
              :func:`gssapi.base.status_utils.displayStatus`)
    :rtype: int or (bool, int, int, int)
    :except GSSError: if there is an error and :param:`return_bool`
                      is set to False
    """


def wrapSizeLimit(ctx, output_size, confidential=True, qop=None):
    """
    Calculates the Max Message Size

    This method calculates the maxium size that a message can be
    in order to have the wrapped message fit within the given size.

    :param ctx: the current security context
    :param int output_size: the desired maxiumum wrapped message size
    :param bool conf_req: whether or not encryption is to be used when
                          wrapping the message
    :param qop: the desired Quality of Protection (or None for default)
    :type qop: int or None
    :returns: the max unwrapped message size
    :rtype: int
    """


def wrap(context, message, confidential=True, qop=None):
    """
    Wraps a message

    This method wraps a message with a MIC and potentially encrypts the message
    using the requested QoP

    :param bytes context: the context of the current connection
    :param message: the message to encrypt
    :type message: (unicode) str or bytes
    :param bool confidential: whether or not to use confidentiality
    :param qop: specifies the quality of protection required
                (use None for the default)
    :type qop: int or None
    :rtype: (bytes, bool)
    :returns: a tuple containing the output message
              and whether confidentiality was used
    :except GSSError:
    """


def unwrap(context, message):
    """
    Unwraps a wrapped message

    This method unwraps a message that was previously
    wrapped by the other party

    :param bytes context: the context of the current connection
    :param bytes message: the input message
    :rtype: (bytes, bool, int)
    :returns: a tuple containing
              the decrypted message,
              whether confidentiality was used,
              and the QoP used
    :except GSSError:
    """

# TODO(sross): implement inquireContext
# TODO(sross): implement inquireCred (w/ support for by_mech)
# TODO(sross): implement getDisplayName

# TODO(sross): implement importCred and exportCred

# Other Methods To Wrap (eventually):
# * add_cred
# * release_cred
# * process_context_token
# * context_time
# * wrap_size_limit
# * import/export _sec_context
# * get_mic
# * verify_mis
# * compare_name
# * inquire_names_for_mech / inquire_mechs_for_name
# * cannonicalize_name
# * export_name
# * duplicate_name
# * add_oid_set_member
# * inidcate_mechs
# * release_oid_set
# * release_buffer
# * create_empty_oid_set
# * test_oid_set_member
