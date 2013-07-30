GSSAPI="BASE"  # this ensures that a full module is generated by cython

from gssapi.base.cython_types cimport *
from gssapi.base.misc import GSSError
from gssapi.base.cython_converters cimport *

from gssapi.base.types import MechType, NameType


cdef extern from "gssapi.h":
    OM_uint32 gss_import_name(OM_uint32 *min_stat,
                              const gss_buffer_t input_buffer,
                              const gss_OID name_type,
                              gss_name_t *output_name) nogil

    OM_uint32 gss_display_name(OM_uint32 *min_stat,
                               const gss_name_t name,
                               gss_buffer_t output_buffer,
                               gss_OID *output_name_type) nogil

    OM_uint32 gss_compare_name(OM_uint32 *min_stat,
                               const gss_name_t name1,
                               const gss_name_t name2,
                               int *is_equal) nogil

    OM_uint32 gss_export_name(OM_uint32 *min_stat,
                              const gss_name_t name,
                              gss_buffer_t output_buffer) nogil

    OM_uint32 gss_canonicalize_name(OM_uint32 *min_stat,
                                    const gss_name_t input_name,
                                    const gss_OID mech_type,
                                    gss_name_t *output_name) nogil

    OM_uint32 gss_duplicate_name(OM_uint32 *min_stat,
                                 const gss_name_t input_name,
                                 gss_name_t *output_name) nogil

    OM_uint32 gss_release_name(OM_uint32 *min_stat,
                               gss_name_t *name) nogil


cdef class Name:
    """
    A GSS API Name
    """
    # defined in pxd
    # cdef gss_name_t raw_name

    def __dealloc__(self):
        # essentially just releaseName(self), but it is unsafe to call
        # methods
        cdef OM_uint32 maj_stat, min_stat
        if self.raw_name is not NULL:
            maj_stat = gss_release_name(&min_stat, &self.raw_name)
            if maj_stat != GSS_S_COMPLETE:
                raise GSSError(maj_stat, min_stat)
            self.raw_name = NULL


def importName(name, name_type=NameType.hostbased_service):
    """
    importName(name, name_type=NameType.hostbased_service) -> Name
    Convert a string and a NameType into a GSSAPI name.

    This method takes a string name and a name type and converts
    it into a GSSAPI Name.

    Args:
        name (bytes): the string version of the name
        name_type (NameType): the type of this name

    Returns:
        Name: the GSSAPI version of the name

    Raises:
        GSSError
    """
    cdef gss_OID nt = c_get_name_type_oid(name_type)

    cdef gss_buffer_desc name_buffer = gss_buffer_desc(0, NULL)  # GSS_C_EMPTY_BUFFER
    name_buffer.length = len(name)
    name_buffer.value = name

    cdef gss_name_t output_name

    cdef OM_uint32 maj_stat, min_stat

    with nogil:
        maj_stat = gss_import_name(&min_stat, &name_buffer,
                                   nt, &output_name)

    cdef Name on = Name()
    if maj_stat == GSS_S_COMPLETE:
        on.raw_name = output_name
        return on
    else:
        raise GSSError(maj_stat, min_stat)

def displayName(Name name):
    """
    displayName(name) -> (bytes, NameType)
    Convert a GSSAPI name into its components.

    This method converts a GSSAPI name back into its text and
    NameType parts.

    Args:
        name (Name): the name in question

    Returns:
        (bytes, NameType): the text part of the name and its type

    Raises:
        GSSError
    """
    cdef gss_buffer_desc output_buffer = gss_buffer_desc(0, NULL)  # GSS_C_EMPTY_BUFFER
    cdef gss_OID name_type

    cdef OM_uint32 maj_stat, min_stat

    with nogil:
        maj_stat = gss_display_name(&min_stat, name.raw_name,
                                    &output_buffer, &name_type)

    if maj_stat == GSS_S_COMPLETE:
        text = output_buffer.value[:output_buffer.length]
        gss_release_buffer(&min_stat, &output_buffer)
        return (text, c_create_name_type(name_type))


def compareName(Name name1, Name name2):
    """
    compareName(name1, name2) -> bool
    Check two GSSAPI names to see if they are the same.

    This method compares two GSSAPI names, checking to
    see if they are equivalent.

    Args:
        name1 (Name): the first name to compare
        name2 (Name): the second name to compare

    Returns:
        bool: whether or not the names are equal

    Raises:
        GSSError
    """
    cdef int is_equal

    cdef OM_uint32 maj_stat, min_stat

    maj_stat = gss_compare_name(&min_stat, name1.raw_name,
                                name2.raw_name, &is_equal)

    if maj_stat == GSS_S_COMPLETE:
        return <bint>is_equal
    else:
        raise GSSError(maj_stat, min_stat)


def exportName(Name name):
    """
    exportName(name) -> bytes
    Export a GSSAPI Mechanim Name.

    This method "produces a canonical contigous string representation
    of a mechanism name, suitable for direct comparison for use in
    authorization functions".  The input name must be a valid GSSAPI
    mechanism name, as generated by canonicalizeName or acceptSecContext.

    Note:
        A mechanism name does not, in fact, refer to the name of a
        mechanism.  Instead, it refers to a canonicalized name,
        such as the initiator name return by acceptSecContext

    Args:
        name (Name): the name to export

    Returns:
        bytes: the exported name

    Raises:
        GSSError
    """
    cdef gss_buffer_desc exported_name = gss_buffer_desc(0, NULL)  # GSS_C_EMPTY_BUFFER

    cdef OM_uint32 maj_stat, min_stat

    maj_stat = gss_export_name(&min_stat, name.raw_name, &exported_name)

    if maj_stat == GSS_S_COMPLETE:
        # force conversion to a python string with the specified length
        # (we use the slice to tell cython that we know the length already)
        res = exported_name.value[:exported_name.length]
        return res
    else:
        raise GSSError(maj_stat, min_stat)

def canonicalizeName(Name name, mech_type):
    """
    canoncializeName(name, mech_type) -> Name
    Canonicalize an arbitrary GSSAPI Name into a Mechanism Name

    This method turns any GSSAPI name into a "mechanism name",
    i.e. a name that would be returned as an initiator princiapl
    from acceptSecContext.

    Args:
        name (Name): the name to canonicalize
        mech_type (MechType): the mechanism type to use to
            canonicalize the name

    Returns:
        Name: a canonicalized version of the input name

    Raises:
        GSSError
    """
    cdef gss_OID mech_oid = c_get_mech_oid(mech_type)
    cdef gss_name_t canonicalized_name

    cdef OM_uint32 maj_stat, min_stat

    with nogil:
        maj_stat = gss_canonicalize_name(&min_stat, name.raw_name,
                                         mech_oid, &canonicalized_name)

    cdef Name cn = Name()
    if maj_stat == GSS_S_COMPLETE:
        cn.raw_name = canonicalized_name
        return cn
    else:
        raise GSSError(maj_stat, min_stat)


def duplicateName(Name name):
    """
    duplicateName(name) -> Name
    Duplicate a GSSAPI Name

    Args:
        name (Name): the name to duplicate

    Returns:
        Name: a duplicate of the input name

    Raises:
        GSSError
    """
    cdef gss_name_t new_name

    cdef OM_uint32 maj_stat, min_stat

    maj_stat = gss_duplicate_name(&min_stat, name.raw_name, &new_name)

    cdef Name on = Name()
    if maj_stat == GSS_S_COMPLETE:
        on.raw_name = new_name
        return on
    else:
        raise GSSError(maj_stat, min_stat)


def releaseName(Name name):
    """
    releaseName(name)
    Release a GSSAPI Name.

    Args:
        name (Name): the name in question

    Raises:
    GSSError
    """
    cdef OM_uint32 maj_stat, min_stat
    maj_stat = gss_release_name(&min_stat, &name.raw_name)
    if maj_stat != GSS_S_COMPLETE:
        raise GSSError(maj_stat, min_stat)
    name.raw_name = NULL
