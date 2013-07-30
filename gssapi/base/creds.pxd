from gssapi.base.cython_types cimport gss_cred_id_t

cdef class Creds:
    cdef gss_cred_id_t raw_creds

