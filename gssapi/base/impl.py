from gssapi.base.types import NameType

def importName(name, name_type=NameType.hostbased_service):
    """
    Gets a GSSAPI Name

    This method converts a string name and type into a 'name'
    string usable in future calls to GSSAPI.

    NOTE: This name needs to have its name released when finished

    :param str name: the plain 'name' to obtain
    :param NameType name_type: the type of the name we are passing in
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

# TODO(sross): implement acquireCred to use with cred
# TODO(sross): add support for non-default mechanisms
# TODO(sross): add support for channel bindings
def initSecContext(target_name, cred=None, context=None, mech_type=None, services=[], time=0, channel_bindings=None, input_token=None):
    """
    Initializes a GSS Security Context

    This method initializes a GSSAPI security context
    with the given parameters.

    :param bytes target_name: the name of the target (commonly the server name, retrieved using importName)
    :param str cred: The handle for credentials claimed (returned from acquireCred), or None to use the default initiator principal 
    :param bytes context: The current context, or None if this is the first call
    :param mech_type: the mechanism type (currently only the default mechanism is supported, by passing None)
    :param [RequirementFlag] services: the requested services
    :param int time: the requested TTL for this context (0 uses the default TTL)
    :param channel_bindings: the requested input channel bindings (currently only None is supported)
    :param bytes input_token: the input token (use None for the first call)
    :returns: a tuple containing the (potentially modified) context, the actual mechanism type used, the output token, the actual services provided, the actual TTL for this context, and whether or not a continue is needed (i.e. (context, MechType (NCI), [RequirementFlag] (NCI), bytes, TTL, continue_needed))
    :except GSSError:
    """

def getMechanismType(mech_type):
    """
    Converts a value from the MechType enum into a gss_OID

    Converts a value from the MechType enum into a gss_OID,
    which can be used in GSSAPI methods such as initSecContext

    :param MechType mech_type: the mechanism type
    :returns: a gss_OID capsule representing the selected mechanism type
    """
    """

def wrap(context, message, confidential=True, qop=None):
    """
    Wrap a message

    Wraps a message with a MIC and potentially encrypts the message
    using the requested QoP

    :param bytes context: the context of the current connection
    :param message: the message to encrypt
    :type message: (unicode) str or bytes
    :param bool confidential: whether or not to use confidentiality
    :param qop: specifies the quality of protection required (use None for the default)
    :type qop: int or None
    :rtype: (bytes, bool)
    :returns: a tuple containing the output message and whether confidentiality was used
    :except GSSError:
    """

def unwrap(context, message):
    """
    Unwrap a wrapped message

    Unwrap a message that was previously wrapped by the other party

    :param bytes context: the context of the current connection
    :param bytes message: the input message
    :rtype: (bytes, bool, int)
    :returns: a tuple containing the decrypted message, whether confidentiality was used, and the QoP
    :except GSSError:
    """

# TODO(sross): implement inquireContext
# TODO(sross): implement inquireCred (w/ support for by_mech)
# TODO(sross): implement getDisplayName

# TODO(sross): SERVER SIDE: implement acceptSecContext

# TODO(sross): implement importCred and exportCred

# Other Methods To Wrap (eventually):
# * add_cred
# * release_cred
# * delete_sec_context
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
# * display_status
# * inidcate_mechs
# * release_oid_set
# * release_buffer
# * create_empty_oid_set
# * test_oid_set_member
