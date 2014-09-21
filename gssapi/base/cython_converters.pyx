from libc.string cimport memcmp

from gssapi.base.cython_types cimport *

from gssapi.base.types import MechType, NameType


cdef gss_OID_set c_get_mech_oid_set(object mechs):
    """Convert a list of MechType values into an OID set."""

    cdef gss_OID_set res_set
    cdef OM_uint32 min_stat
    gss_create_empty_oid_set(&min_stat, &res_set)

    if MechType.kerberos in mechs:
        gss_add_oid_set_member(&min_stat, gss_mech_krb5, &res_set)

    return res_set


cdef gss_OID c_get_name_type_oid(object name_type):
    """Get a GSS name type OID from a NameType."""

    if name_type is NameType.hostbased_service:
        return GSS_C_NT_HOSTBASED_SERVICE
    elif name_type is NameType.principal:
        return GSS_KRB5_NT_PRINCIPAL_NAME
    elif name_type is NameType.user:
        return GSS_C_NT_USER_NAME
    elif name_type is NameType.anonymous:
        return GSS_C_NT_ANONYMOUS
    elif name_type is NameType.machine_uid:
        return GSS_C_NT_MACHINE_UID_NAME
    elif name_type is NameType.string_uid:
        return GSS_C_NT_STRING_UID_NAME
    elif name_type is NameType.export:
        return GSS_C_NT_EXPORT_NAME
    else:
        # TODO(sross): raise exception?
        return GSS_C_NO_OID


cdef object c_create_name_type(gss_OID name_type):
    """Convert a GSSAPI name type OID into a NameType."""

    if c_compare_oids(name_type, GSS_C_NT_HOSTBASED_SERVICE):
        return NameType.hostbased_service
    elif c_compare_oids(name_type, GSS_KRB5_NT_PRINCIPAL_NAME):
        return NameType.principal
    elif c_compare_oids(name_type, GSS_C_NT_USER_NAME):
        return NameType.user
    elif c_compare_oids(name_type, GSS_C_NT_ANONYMOUS):
        return NameType.anonymous
    elif c_compare_oids(name_type, GSS_C_NT_MACHINE_UID_NAME):
        return NameType.machine_uid
    elif c_compare_oids(name_type, GSS_C_NT_STRING_UID_NAME):
        return NameType.string_uid
    elif c_compare_oids(name_type, GSS_C_NT_EXPORT_NAME):
        return NameType.export
    else:
        return None


cdef gss_OID c_get_mech_oid(object mech_type):
    """Get a mechanism's OID from a MechType."""

    if mech_type is MechType.kerberos:
        return gss_mech_krb5
    else:
        # TODO(sross): raise exception?
        return GSS_C_NO_OID

cdef inline bint c_compare_oids(gss_OID a, gss_OID b):
    """Compare two OIDs to see if they are the same."""

    return (a.length == b.length and
            not memcmp(a.elements, b.elements, a.length))

cdef object c_create_mech_type(gss_OID_desc mech_type):
    """Convert a GSS mechanism OID into a MechType."""

    if c_compare_oids(&mech_type, gss_mech_krb5):
        return MechType.kerberos
    else:
        return None

cdef object c_create_mech_list(gss_OID_set mech_set, bint free=True):
    """Convert a set of GSS mechanism OIDs to a list of MechType values."""

    l = []
    cdef i
    for i in range(mech_set.count):
        mech_type = c_create_mech_type(mech_set.elements[i])
        if mech_type is not None:
            l.append(mech_type)

    cdef OM_uint32 tmp_min_stat
    if free:
        gss_release_oid_set(&tmp_min_stat, &mech_set)

    return l
