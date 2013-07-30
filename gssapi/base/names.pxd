from gssapi.base.cython_types cimport gss_name_t

cdef class Name:
    cdef gss_name_t raw_name
