from gssapi.base.cython_types cimport *
from gssapi.base.types import MechType, NameType

cdef gss_OID_set c_get_mech_oid_set(object mechs)
cdef gss_OID c_get_name_type_oid(object name_type)
cdef object c_create_name_type(gss_OID name_type)
cdef gss_OID c_get_mech_oid(object mech_type)
cdef inline bint c_compare_oids(gss_OID a, gss_OID b)
cdef object c_create_mech_type(gss_OID_desc mech_type)
cdef object c_create_mech_list(gss_OID_set mech_set)
