GSSAPI="BASE"  # tihs ensures that a full module is generated by cython

from gssapi.base.cython_types cimport *
from gssapi.base.cython_converters cimport *
from gssapi.base.creds cimport Creds
from gssapi.base.names cimport Name

from libc.string import memcmp

from gssapi.base.types import MechType, RequirementFlag
from gssapi.base.misc import GSSError


cdef extern from "gssapi.h":
    OM_uint32 gss_init_sec_context(OM_uint32 *min_stat,
                                   const gss_cred_id_t initiator_creds,
                                   gss_ctx_id_t *context,
                                   const gss_name_t target_name,
                                   const gss_OID mech_type,
                                   OM_uint32 flags,
                                   OM_uint32 ttl,
                                   const gss_channel_bindings_t channel_bindings,
                                   const gss_buffer_t input_token,
                                   gss_OID *actual_mech_type,
                                   gss_buffer_t output_token,
                                   OM_uint32 *actual_flags,
                                   OM_uint32 *actual_ttl) nogil


    OM_uint32 gss_accept_sec_context(OM_uint32 *min_stat,
                                     gss_ctx_id_t *context,
                                     const gss_cred_id_t acceptor_creds,
                                     const gss_buffer_t input_token,
                                     const gss_channel_bindings_t channel_bindings,
                                     const gss_name_t *initiator_name,
                                     gss_OID *mech_type,
                                     gss_buffer_t output_token,
                                     OM_uint32 *flags,
                                     OM_uint32 *ttl,
                                     gss_cred_id_t *delegated_creds) nogil

    OM_uint32 gss_delete_sec_context(OM_uint32 *min_stat,
                                     gss_ctx_id_t *context,
                                     gss_buffer_t output_token) nogil

    OM_uint32 gss_process_context_token(OM_uint32 *min_stat,
                                        const gss_ctx_id_t context,
                                        const gss_buffer_t token) nogil

    OM_uint32 gss_context_time(OM_uint32 *min_stat,
                               const gss_ctx_id_t context_handle,
                               OM_uint32 *ttl) nogil

    OM_uint32 gss_inquire_context(OM_uint32 *min_stat,
                                  const gss_ctx_id_t context,
                                  gss_name_t *initiator_name,
                                  gss_name_t *target_name,
                                  OM_uint32 *ttl,
                                  gss_OID *mech_type,
                                  OM_uint32 *ctx_flags,
                                  int *locally_initiated,
                                  int *is_open) nogil

    OM_uint32 gss_export_sec_context(OM_uint32 *min_stat,
                                     gss_ctx_id_t *context,
                                     gss_buffer_t interprocess_token) nogil

    OM_uint32 gss_import_sec_context(OM_uint32 *min_stat,
                                     const gss_buffer_t interprocess_token,
                                     gss_ctx_id_t *context) nogil


cdef class SecurityContext:
    """
    A GSSAPI Context
    """
    # defined in pxd
    # cdef gss_ctx_id_t raw_ctx

    def __dealloc__(self):
        # basically just deleteSecContext, but we are not
        # allowed to call methods here
        cdef OM_uint32 maj_stat, min_stat
        if self.raw_ctx is not NULL:
            maj_stat = gss_delete_sec_context(&min_stat, &self.raw_ctx,
                                              <gss_buffer_t>GSS_C_EMPTY_BUFFER)
            if maj_stat != GSS_S_COMPLETE:
                raise GSSError(maj_stat, min_stat)

            self.raw_ctx = NULL


cdef inline object c_create_flags_list(OM_uint32 flags):
    return [flag for flag in RequirementFlag if int(flag) & flags > 0]


cdef OM_uint32 c_parse_flags(object flags):
    """
    Convert a list of RequirementFlag values to an int
    """

    cdef OM_uint32 res = 0

    for flag in flags:
        res = res | int(flag)

# TODO(sross): add support for channel bindings
def initSecContext(Name target_name not None, Creds cred=None,
                   SecurityContext context=None,
                   mech_type=None,
                   flags=None, ttl=0, channel_bindings=None,
                   input_token=None):
    """
    initSecContext(target_name, cred=None, context=None, mech_type=None, flags=None, tll=0, channel_bindings=None, input_token=None) -> (SecurityContext, MechType, [RequirementFlag], bytes, int, bool)
    Initiate a GSSAPI Security Context.

    This method initiates a GSSAPI security context, targeting the given
    target name.  To create a basic context, just provide the target name.
    Further calls used to update the context should pass in the output context
    of the last call, as well as the input token received from the acceptor.

    Warning:
        This changes the input context!

    Args:
        target_name (Name): the target for the security context
        cred (Creds): the credentials to use to initiate the context,
            or None to use the default credentials
        context (SecurityContext): the security context to update, or
            None to create a new context
        mech_type (MechType): the mechanism type for this security context,
            or None for the default mechanism type
        flags ([RequirementFlag]): the flags to request for the security context,
            or None to use the default set: mutual_authentication and 
            out_of_sequence_detection
        ttl (int): the request lifetime of the security context
        channel_bindings (ChannelBindings): NCI
        input_token (bytes): the token to use to update the security context,
            or None if you are creating a new context
    
    Returns:
        (SecurityContext, MechType, [RequirementFlag], bytes, int, bool): the
            output security context, the actual mech type, the actual flags
            used, the output token to send to the acceptor, the actual
            lifetime of the context, and whether or not more calls
            are needed to finish the initiation.

    Raises:
        GSSError
    """
    cdef gss_OID mech_oid = c_get_mech_oid(mech_type) if mech_type is not None else GSS_C_NO_OID
    cdef OM_uint32 req_flags = c_parse_flags(flags or [])
    cdef gss_channel_bindings_t bdng = GSS_C_NO_CHANNEL_BINDINGS
    cdef gss_buffer_desc input_token_buffer = gss_buffer_desc(0, NULL)  # GSS_C_EMPTY_BUFFER
    cdef OM_uint32 input_ttl = ttl

    if input_token is not None:
        input_token_buffer.value = input_token
        input_token_buffer.length = len(input_token)

    cdef gss_OID actual_mech_type
    cdef gss_buffer_desc output_token_buffer = gss_buffer_desc(0, NULL)  # GSS_C_EMPTY_BUFFER
    cdef OM_uint32 ret_flags
    cdef OM_uint32 output_ttl

    cdef OM_uint32 maj_stat, min_stat

    with nogil:
        maj_stat = gss_init_sec_context(&min_stat, cred.raw_creds,
                                        &context.raw_ctx,
                                        target_name.raw_name,
                                        mech_oid, req_flags, input_ttl,
                                        bdng, &input_token_buffer,
                                        &actual_mech_type,
                                        &output_token_buffer,
                                        &ret_flags, &output_ttl)

    if maj_stat == GSS_S_COMPLETE or maj_stat == GSS_S_CONTINUE_NEEDED:
        output_context = context  # we just used a pointer, so reuse it
        output_token = output_token_buffer.value[:output_token_buffer.length]
        res = (output_context, c_create_mech_type(actual_mech_type[0]),
               c_create_flags_list(ret_flags), output_token,
               output_ttl, maj_stat == GSS_S_CONTINUE_NEEDED)
        gss_release_buffer(&min_stat, &output_token_buffer)
        return res
    else:
        raise GSSError(maj_stat, min_stat)


def acceptSecContext(input_token, Creds acceptor_cred=None,
                     SecurityContext context=None, channel_bindings=None):
    """
    acceptSecContext(input_token, acceptor_cred=None, context=None, channel_bindings=None) -> (SecurityContext, Name, MechType, bytes, [RequirementFlag], int, Creds, bool)
    Accept a GSSAPI security context.

    This method accepts a GSSAPI security context using a token sent by the initiator, using the given
    credentials.  It can either be used to accept a security context and create a new security context
    object, or to update an existing security context object.

    Warning:
        This changes the input context!

    Args:
        input_token (bytes): the token sent by the context initiator
        acceptor_cred (Creds): the credentials to be used to accept the context
            (or None to use the default credentials)
        context (SecurityContext): the security context to update
            (or None to create a new security context object)
        channel_bindings: NCI

    Returns:
        (SecurityContext, Name, MechType, bytes, [RequirementFlag], int, Creds, bool): the
            resulting security context, the initiator name, the mechanism
            being used, the output token, the flags in use, the lifetime
            of the context, the delegated credentials (valid only if the
            delegate_to_peer flag is set), and whether or not further token
            exchanges are needed to finalize the security context.

    Raises:
        GSSError
    """
    cdef gss_channel_bindings_t bdng = GSS_C_NO_CHANNEL_BINDINGS
    cdef gss_buffer_desc input_token_buffer = gss_buffer_desc(0, NULL)  # GSS_C_EMPTY_BUFFER

    if input_token is not None:
        input_token_buffer.value = input_token
        input_token_buffer.length = len(input_token)

    cdef gss_name_t initiator_name
    cdef gss_OID mech_type
    cdef gss_buffer_desc output_token_buffer = gss_buffer_desc(0, NULL)  # GSS_C_EMPTY_BUFFER
    cdef OM_uint32 ret_flags
    cdef OM_uint32 output_ttl
    cdef gss_cred_id_t delegated_cred

    cdef OM_uint32 maj_stat, min_stat

    with nogil:
        maj_stat = gss_accept_sec_context(&min_stat, &context.raw_ctx,
                                          acceptor_cred.raw_creds,
                                          &input_token_buffer, bdng,
                                          &initiator_name,
                                          &mech_type, &output_token_buffer,
                                          &ret_flags, &output_ttl,
                                          &delegated_cred)

    cdef Name on = Name()
    cdef Creds oc = Creds()
    if maj_stat == GSS_S_COMPLETE or maj_stat == GSS_S_CONTINUE_NEEDED:
        output_token = output_token_buffer.value[:output_token_buffer.length]
        on.raw_name = initiator_name
        oc.raw_creds = delegated_cred
        res = (context, on, c_create_mech_type(mech_type[0]),
               output_token, c_create_flags_list(ret_flags),
               output_ttl, oc,
               maj_stat == GSS_S_CONTINUE_NEEDED)
        gss_release_buffer(&min_stat, &output_token_buffer)
        return res
    else:
        raise GSSError(maj_stat, min_stat)


def deleteSecContext(SecurityContext context):
    """
    deleteSecContext(context) -> bytes
    Delete a GSSAPI Security Context.

    This method deletes a GSSAPI security context,
    returning an output token to send to the other
    holder of the security context to notify them
    of the deletion.

    Args:
        context (SecurityContext): the security context in question

    Returns:
        bytes: the output token
    
    Raises:
        GSSError
    """
    cdef gss_buffer_desc output_token = gss_buffer_desc(0, NULL)  # GSS_C_EMPTY_BUFFER
    cdef OM_uint32 maj_stat, min_stat
    maj_stat = gss_delete_sec_context(&min_stat, &context.raw_ctx,
                                      &output_token)
    if maj_stat == GSS_S_COMPLETE:
        res = output_token.value[:output_token.length]
        context.raw_ctx = NULL
        return res
    else:
        raise GSSError(maj_stat, min_stat)
