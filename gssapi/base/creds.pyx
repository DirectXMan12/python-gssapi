GSSAPI="BASE"  # tihs ensures that a full module is generated by cython

from gssapi.base.cython_types cimport *
from gssapi.base.misc import GSSError
from gssapi.base.cython_converters cimport *
from gssapi.base.names cimport Name

from gssapi.base.types import MechType, NameType


cdef extern from "gssapi.h":
    OM_uint32 gss_acquire_cred(OM_uint32 *min_stat,
                               const gss_name_t name,
                               OM_uint32 ttl,
                               const gss_OID_set mechs,
                               gss_cred_usage_t cred_usage,
                               gss_cred_id_t *creds,
                               gss_OID_set *actual_mechs,
                               OM_uint32 *actual_ttl) nogil

    OM_uint32 gss_release_cred(OM_uint32 *min_stat,
                               gss_cred_id_t *creds) nogil

    OM_uint32 gss_acquire_cred_impersonate_name(OM_uint32 *min_stat,
                                                const gss_cred_id_t impersonator_creds,
                                                const gss_name_t name,
                                                OM_uint32 ttl,
                                                const gss_OID_set mechs,
                                                gss_cred_usage_t cred_usage,
                                                gss_cred_id_t *output_creds,
                                                gss_OID_set *actual_mechs,
                                                OM_uint32 *actual_ttl) nogil

    OM_uint32 gss_add_cred(OM_uint32 *min_stat,
                           const gss_cred_id_t base_creds,
                           const gss_name_t name,
                           const gss_OID mech,
                           gss_cred_usage_t cred_usage,
                           OM_uint32 initiator_ttl,
                           OM_uint32 acceptor_ttl,
                           gss_cred_id_t *output_creds,
                           gss_OID_set *actual_mechs,
                           OM_uint32 *actual_initiator_ttl,
                           OM_uint32 *actual_acceptor_ttl) nogil

    OM_uint32 gss_add_cred_impersonate_name(OM_uint32 *min_stat,
                                            gss_cred_id_t base_creds,
                                            const gss_cred_id_t impersonator_creds,
                                            const gss_name_t name,
                                            const gss_OID mech,
                                            gss_cred_usage_t cred_usage,
                                            OM_uint32 initiator_ttl,
                                            OM_uint32 acceptor_ttl,
                                            gss_cred_id_t *output_creds,
                                            gss_OID_set *actual_mechs,
                                            OM_uint32 *actual_initiator_ttl,
                                            OM_uint32 *actual_acceptor_ttl) nogil

    OM_uint32 gss_inquire_cred(OM_uint32 *min_stat,
                               const gss_cred_id_t creds,
                               gss_name_t *name,
                               OM_uint32 *ttl,
                               gss_cred_usage_t *cred_usage,
                               gss_OID_set *mechs) nogil

    OM_uint32 gss_inquire_cred_by_mech(OM_uint32 *min_stat,
                                       const gss_cred_id_t cred_handle,
                                       const gss_OID mech_type,
                                       gss_name_t *name,
                                       OM_uint32 *initiator_ttl,
                                       OM_uint32 *acceptor_ttl,
                                       gss_cred_usage_t *cred_usage) nogil


cdef class Creds:
    """
    GSSAPI Credentials
    """
    # defined in pxd
    # cdef gss_cred_id_t raw_creds

    def __cinit__(self, Creds cpy=None):
        if cpy is not None:
            self.raw_creds = cpy.raw_creds
            cpy._free_on_dealloc = False

        self._free_on_dealloc = True

    def __dealloc__(self):
        # essentially just releaseCred(self), but it is unsafe to call
        # methods
        cdef OM_uint32 maj_stat, min_stat
        if self.raw_creds is not NULL and self._free_on_dealloc:
            maj_stat = gss_release_cred(&min_stat, &self.raw_creds)
            if maj_stat != GSS_S_COMPLETE:
                raise GSSError(maj_stat, min_stat)
            self.raw_creds = NULL


def acquireCred(Name name, ttl=0, mechs=None, cred_usage='both'):
    """
    acquireCred(name, ttl=0, mechs=None, cred_usage='both') -> (Creds, [MechType], int)
    Get GSSAPI credentials for the given name and mechanisms.

    This method gets GSSAPI credentials corresponding to the given name and mechanims.
    The desired TTL and usage for the the credential may also be specified.

    Args:
        name (Name): the name for which to acquire the credentials
        ttl (int): the lifetime for the credentials
        mechs ([MechType]): the desired mechanisms for which the credentials should work,
            or None for the default set
        cred_usage (str): the usage type for the credentials: may be
            'initiate', 'accept', or 'both'

    Returns:
        (Creds, [MechType], int): the resulting credentials, the actual
            mechanisms with which they may be used, and their actual
            lifetime

    Raises:
        GSSError
    """

    cdef gss_OID_set desired_mechs = c_get_mech_oid_set(mechs) if mechs is not None else GSS_C_NO_OID_SET
    cdef OM_uint32 input_ttl = ttl
    cdef gss_cred_usage_t usage
    cdef gss_name_t c_name = name.raw_name

    if cred_usage == 'initiate':
        usage = GSS_C_INITIATE
    elif cred_usage == 'accept':
        usage = GSS_C_ACCEPT
    else:
        usage = GSS_C_BOTH

    cdef gss_cred_id_t creds
    cdef gss_OID_set actual_mechs
    cdef OM_uint32 actual_ttl

    cdef OM_uint32 maj_stat, min_stat

    with nogil:
        maj_stat = gss_acquire_cred(&min_stat, c_name, input_ttl,
                                    desired_mechs, usage, &creds,
                                    &actual_mechs, &actual_ttl)

    cdef OM_uint32 tmp_min_stat
    if mechs is not None:
        gss_release_oid_set(&tmp_min_stat, &desired_mechs)

    cdef Creds rc = Creds()
    if maj_stat == GSS_S_COMPLETE:
        rc.raw_creds = creds
        return (rc, c_create_mech_list(actual_mechs), actual_ttl)
    else:
        raise GSSError(maj_stat, min_stat)


def releaseCred(Creds creds):
    """
    releaseCred(creds)
    Release GSSAPI Credentials.

    This method releases GSSAPI credentials.

    Args:
        creds (Creds): the credentials in question

    Raises:
        GSSError
    """
    cdef OM_uint32 maj_stat, min_stat
    maj_stat = gss_release_cred(&min_stat, &creds.raw_creds)
    if maj_stat != GSS_S_COMPLETE:
        raise GSSError(maj_stat, min_stat)
    creds.raw_creds = NULL
