from gssapi.base.types import NameType


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
                   services=[], time=0, channel_bindings=None,
                   input_token=None):
    """
    Initializes a GSS Security Context

    (Client)
    This method initializes a GSSAPI security context
    with the given parameters.

    :param target_name: the name of the target
                        (commonly the server name, retrieved using importName)
    :param cred: The handle for credentials claimed
                 (returned from acquireCred),
                 or None to use the default initiator principal
    :param context: The current context, or None if this is the first call
    :param mech_type: the mechanism type
                      (None for default, otherwise a capsule
                      from :func:`getMechanismType`)
    :param services: the requested services
    :type services: [:class:`RequirementFlag`]
    :param int time: the requested TTL for this context
                     (0 uses the default TTL)
    :param channel_bindings: the requested input channel bindings
                             (currently only None is supported)
    :param bytes input_token: the input token (use None for the first call)
    :returns: a tuple containing
              the (potentially modified) context,
              the actual mechanism type used,
              the output token,
              the actual services provided,
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
              the services flags in use,
              the TTL for the context,
              and the delegated credential handle
                (or None if
                 RequirementFlags.delegate_to_peer is not present
                 in the services flags)
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
