#include <Python.h>
#include <gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <stdio.h>

#define DEBUG(mn, str, args...) printf("  %s: " str "\n", mn, args)

PyObject *GSSError_class;
PyObject *RequirementFlag_class;
PyObject *MechType_class;

/* Utility method to raise an error */
static void raise_gss_error(OM_uint32 maj, OM_uint32 min)
{
    PyErr_SetObject(GSSError_class, Py_BuildValue("II", maj, min));
}

static PyObject *
importName(PyObject *self, PyObject *args)
{
    char *name;
    int name_len;
    int raw_name_type = 0; /* default: hostbased_service */

    if(!PyArg_ParseTuple(args, "s#|i", &name, &name_len, &raw_name_type))
        return NULL;

    gss_OID name_type;
    switch(raw_name_type) {
        case 0:
            name_type = GSS_C_NT_HOSTBASED_SERVICE;
            break;
        case 1:
            name_type = GSS_KRB5_NT_PRINCIPAL_NAME;
            break;
        case 2:
            name_type = GSS_C_NT_USER_NAME;
            break;
        case 3:
            name_type = GSS_C_NT_ANONYMOUS;
            break;
        case 4:
            name_type = GSS_C_NT_MACHINE_UID_NAME;
            break;
        case 5:
            name_type = GSS_C_NT_STRING_UID_NAME;
            break;
        case 6:
            name_type = GSS_C_NT_EXPORT_NAME;
            break;
        default:
            name_type = NULL;
            /* TODO(sross): throw error */
            break;
    }

    gss_buffer_desc name_token = GSS_C_EMPTY_BUFFER;
    name_token.length = name_len;
    name_token.value = name;

    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    gss_name_t output_name;

    Py_BEGIN_ALLOW_THREADS
        maj_stat = gss_import_name(&min_stat, &name_token,
                                   name_type, &output_name);
    Py_END_ALLOW_THREADS

    if (maj_stat == GSS_S_COMPLETE) {
        PyObject *out_name_obj = PyCapsule_New(output_name, NULL, NULL);
        return out_name_obj;
    }
    else {
        raise_gss_error(maj_stat, min_stat);
        return NULL;
    }
}

#define GET_CAPSULE(type, obj) (type)PyCapsule_GetPointer(obj, NULL)
#define GET_CAPSULE_DEREF(type, obj) *((type*)PyCapsule_GetPointer(obj, NULL))

static PyObject *
releaseName(PyObject *self, PyObject *args)
{
    PyObject *name_obj;

    if (!PyArg_ParseTuple(args, "O", &name_obj))
        return NULL;

    gss_name_t name = GET_CAPSULE(gss_name_t, name_obj);

    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    maj_stat = gss_release_name(&min_stat, &name);

    if (maj_stat == GSS_S_COMPLETE) {
        Py_RETURN_NONE;
    }
    else {
       raise_gss_error(maj_stat, min_stat);
       return NULL;
    }
}

#define COMPARE_OIDS(a,b) ( (a->length == b->length) && \
                            !memcmp(a->elements, b->elements, a->length) )

static PyObject *
createMechType(gss_OID mech_type)
{
    if (COMPARE_OIDS(mech_type, gss_mech_krb5)) {
        /* return MechType.kerberos */
        PyObject *argList = Py_BuildValue("(I)", 0);
        PyObject *res = PyObject_CallObject(MechType_class, argList);
        Py_DECREF(argList);
        return res;
    }
    else {
        Py_RETURN_NONE;
    }
}

static PyObject *
createMechList(gss_OID_set mechs)
{
    PyObject *list = PyList_New(0);
    int i;
    for (i = 0; i < mechs->count; i++) {
        PyObject *mech = createMechType(&(mechs->elements[i]));

        if (mech != Py_None) {
            PyList_Append(list, mech);
        }

        Py_DECREF(Py_None);
    }

    return list;
}

#define INT_CHECK_AND_ADD_TO_SET(list, pval, cval, set) \
    do { \
        PyObject *num = PyInt_FromLong(pval); \
        CHECK_AND_ADD_TO_SET(list, pval, cval, set); \
        Py_DECREF(num); \
    } while(0);

#define CHECK_AND_ADD_TO_SET(list, pval, cval, set) \
    if (PySequence_Contains(list, pval)) { \
        OM_uint32 min_stat_add; \
        gss_add_oid_set_member(&min_stat_add, cval, &set); \
    }

static gss_OID_set
createOIDMechSet(PyObject *list)
{
    OM_uint32 min_stat_create;
    gss_OID_set set;
    gss_create_empty_oid_set(&min_stat_create, &set);

    /* MechType.kerberos = 0 */
    INT_CHECK_AND_ADD_TO_SET(list, 0, gss_mech_krb5, set);

    return set;
}

#define CAPSULE_OR_DEFAULT(type, obj, def) \
            ( obj == Py_None ? def : GET_CAPSULE(type, obj))

#define CAP_OR_DFLT_DR(type, obj, def) \
            ( obj == Py_None ? def : GET_CAPSULE_DEREF(type, obj))

#define VALUE_OR_DEFAULT(obj, val, def) \
            ( obj == Py_None ? def : val )

#define TRUE_FALSE_NONE(obj, t, f, n) \
            ( obj == Py_None ? n : ( PyLong_AsLong(obj) ? t : f ))

static PyObject *
acquireCred(PyObject *self, PyObject *args, PyObject *keywds)
{
    PyObject *raw_desired_name; /* capsule */
    OM_uint32 input_ttl = 0; /* default: 0 */
    PyObject *raw_mechs = Py_None; /* capsule or default: None */
    PyObject *raw_cred_usage = Py_None; /* boolean or default: None */

    static char *kwlist[]  = {"name", "ttl", "mechs", "cred_usage", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "O|IOO", kwlist,
                                     &raw_desired_name, &input_ttl,
                                     &raw_mechs, &raw_cred_usage))
        return NULL;

    gss_name_t desired_name = GET_CAPSULE(gss_name_t, raw_desired_name);

    gss_OID_set desired_mechs = VALUE_OR_DEFAULT(raw_mechs,
                                                 createOIDMechSet(raw_mechs),
                                                 GSS_C_NO_OID_SET);

    gss_cred_usage_t cred_usage = TRUE_FALSE_NONE(raw_cred_usage,
                                                  GSS_C_ACCEPT,
                                                  GSS_C_INITIATE,
                                                  GSS_C_BOTH);

    gss_cred_id_t creds;
    gss_OID_set actual_mechs;
    OM_uint32 actual_ttl;

    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    Py_BEGIN_ALLOW_THREADS
        maj_stat = gss_acquire_cred(&min_stat, desired_name, input_ttl,
                                    desired_mechs, cred_usage, &creds,
                                    &actual_mechs, &actual_ttl);
    Py_END_ALLOW_THREADS


    if (raw_mechs != Py_None) {
        OM_uint32 min_stat_release;
        gss_release_oid_set(&min_stat_release, &desired_mechs);
    }

    if (maj_stat == GSS_S_COMPLETE) {
        PyObject *cap_creds = PyCapsule_New(creds, NULL, NULL);
        PyObject *list_mechs = createMechList(actual_mechs);
        PyObject *res = Py_BuildValue("OOI",
                                      cap_creds, list_mechs, actual_ttl);
        Py_DECREF(cap_creds);
        Py_DECREF(list_mechs);
        return res;
    }
    else {
        raise_gss_error(maj_stat, min_stat);
        return NULL;
    }
}

static PyObject *
releaseCred(PyObject *self, PyObject *args)
{
    PyObject *raw_creds;

    if (!PyArg_ParseTuple(args, "O", &raw_creds))
        return NULL;

    gss_cred_id_t creds = GET_CAPSULE(gss_cred_id_t, raw_creds);

    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    maj_stat = gss_release_cred(&min_stat, &creds);

    if (maj_stat == GSS_S_COMPLETE) {
        Py_RETURN_NONE;
    }
    else {
       raise_gss_error(maj_stat, min_stat);
       return NULL;
    }
}

static PyObject *
deleteSecContext(PyObject *self, PyObject *args)
{
    PyObject *raw_context; /* capsule */
    int output_needed = 0; /* boolean, default: False */

    if(!PyArg_ParseTuple(args, "O|i", &raw_context, &output_needed))
        return NULL;

    gss_ctx_id_t ctx = GET_CAPSULE(gss_ctx_id_t, raw_context);

    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    if (output_needed) {
        maj_stat = gss_delete_sec_context(&min_stat, &ctx, &output_token);
    }
    else {
        maj_stat = gss_delete_sec_context(&min_stat, &ctx, GSS_C_NO_BUFFER);
    }


    if (maj_stat == GSS_S_COMPLETE) {
        if (output_needed) {
            PyObject *res = Py_BuildValue("s#", output_token.value,
                                          output_token.length);
            gss_release_buffer(&min_stat, &output_token);
            return res;
        }
        else {
            Py_RETURN_NONE;
        }
    }
    else {
        raise_gss_error(maj_stat, min_stat);
        return NULL;
    }
}

static PyObject *
getMechanismType(PyObject *self, PyObject *args)
{
    int raw_mech_type; /* MechType (int) */

    if (!PyArg_ParseTuple(args, "i", &raw_mech_type))
        return NULL;

    gss_OID mech_type;

    switch (raw_mech_type) {
        case 0:
            mech_type = gss_mech_krb5;
            break;
        default:
            /* TODO(sross): raise exception */
            mech_type = GSS_C_NO_OID;
            break;
    }

    PyObject *cap_mech_type = PyCapsule_New(mech_type, NULL, NULL);
    return cap_mech_type;
}

static int
parseFlags(PyObject *flags_list, int default_flags)
{
    if (flags_list == Py_None || flags_list == NULL) {
        return default_flags;
    }

    int cflags = 0;

    int i;
    for (i = 0; i < PyList_Size(flags_list); i++) {
        PyObject *raw_item = PyList_GetItem(flags_list, i);
        int flag = PyInt_AsLong(PyNumber_Int(raw_item));
        cflags = cflags | flag;
    }

    return cflags;
}

#define CHECK_AND_INIT_FLAG(name) \
    if (cflags & GSS_C_ ## name ## _FLAG) \
    { \
        PyObject *argList = Py_BuildValue("(I)", GSS_C_ ## name ## _FLAG); \
        PyObject *resItem = PyObject_CallObject(RequirementFlag_class, \
                                                argList); \
        PyList_Append(flag_list, resItem); \
        Py_XDECREF(resItem); \
        Py_DECREF(argList); \
    }

static PyObject *
createFlagsList(int cflags)
{
    PyObject *flag_list = PyList_New(0);

    CHECK_AND_INIT_FLAG(DELEG)
    CHECK_AND_INIT_FLAG(MUTUAL)
    CHECK_AND_INIT_FLAG(REPLAY)
    CHECK_AND_INIT_FLAG(SEQUENCE)
    CHECK_AND_INIT_FLAG(CONF)
    CHECK_AND_INIT_FLAG(INTEG)
    CHECK_AND_INIT_FLAG(ANON)
    CHECK_AND_INIT_FLAG(TRANS)

    return flag_list;
}

static PyObject *
acceptSecContext(PyObject *self, PyObject *args, PyObject *keywds)
{
    char *raw_input_token = NULL; /* not null terminated, default: None/NULL */
    int raw_input_token_len;
    PyObject *raw_acceptor_cred = Py_None; /* capsule of default: None */
    PyObject *raw_ctx = Py_None; /* capsule or default: None */
    PyObject *raw_channel_bindings = Py_None; /* capsule or default: None */

    static char *kwlist[] = {"input_token", "acceptor_cred", "ctx", "channel_bindings", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s#|OOO", kwlist,
                                     &raw_input_token, &raw_input_token_len,
                                     &raw_acceptor_cred, &raw_ctx,
                                     &raw_channel_bindings))
        return NULL;


    /* NOTE: a server SHOULD use a credential obtained by calling acquireCred or
     *       addCred for the GSS_C_NO_NAME desired_name and OID of kerberos for the
     *       mech type, but may use either GSS_C_NO_CREDENTIAL or aqquire/add cred for
     *       the server's principal name and the kerberos mechanism
     *
     *       We use the easiest way for the default for now :-)
     */
    gss_cred_id_t acceptor_cred = CAPSULE_OR_DEFAULT(gss_cred_id_t,
                                                     raw_acceptor_cred,
                                                     GSS_C_NO_CREDENTIAL);

    gss_ctx_id_t ctx = CAPSULE_OR_DEFAULT(gss_ctx_id_t, raw_ctx,
                                          GSS_C_NO_CONTEXT);

    gss_channel_bindings_t bdng = CAP_OR_DFLT_DR(gss_channel_bindings_t,
                                                 raw_channel_bindings,
                                                 GSS_C_NO_CHANNEL_BINDINGS);

    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;

    if (raw_input_token && *raw_input_token)
    {
        input_token.length = raw_input_token_len;
        input_token.value = raw_input_token;
    }

    gss_name_t src_name;
    gss_OID mech_type; /* read-only (don't free) */
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 ret_flags;
    OM_uint32 output_ttl;
    gss_cred_id_t delegated_cred;

    OM_uint32 maj_stat;
    OM_uint32 min_stat;


    Py_BEGIN_ALLOW_THREADS
        maj_stat = gss_accept_sec_context(&min_stat, &ctx, acceptor_cred,
                                          &input_token, bdng, &src_name,
                                          &mech_type, &output_token,
                                          &ret_flags, &output_ttl,
                                          &delegated_cred);
    Py_END_ALLOW_THREADS


    if (maj_stat == GSS_S_COMPLETE || maj_stat == GSS_S_CONTINUE_NEEDED) {
        PyObject *cap_ctx = PyCapsule_New(ctx, NULL, NULL);
        PyObject *cap_src_name = PyCapsule_New(src_name, NULL, NULL);
        PyObject *cap_mech_type = createMechType(mech_type);
        PyObject *reqs_out = createFlagsList(ret_flags);

        PyObject *cap_delegated_cred;
        if (delegated_cred == GSS_C_NO_CREDENTIAL) {
            cap_delegated_cred = Py_None;
            Py_INCREF(Py_None);
        }
        else {
            cap_delegated_cred = PyCapsule_New(delegated_cred, NULL, NULL);
        }

        PyObject *continue_needed;
        if (maj_stat == GSS_S_CONTINUE_NEEDED) {
            continue_needed = Py_True;
            Py_INCREF(Py_True);
        }
        else {
            continue_needed = Py_False;
            Py_INCREF(Py_False);
        }

        PyObject *res = Py_BuildValue("OOOs#OIOO", cap_ctx, cap_src_name,
                                      cap_mech_type, output_token.value,
                                      output_token.length, reqs_out,
                                      output_ttl, cap_delegated_cred,
                                      continue_needed);
        gss_release_buffer(&min_stat, &output_token);
        Py_DECREF(reqs_out);
        Py_DECREF(cap_ctx);
        Py_DECREF(cap_src_name);
        Py_DECREF(cap_mech_type);
        Py_DECREF(cap_delegated_cred);
        Py_DECREF(continue_needed);
        return res;
    }
    else
    {
        raise_gss_error(maj_stat, min_stat);
        return NULL;
    }

}

static PyObject *
initSecContext(PyObject *self, PyObject *args, PyObject *keywds)
{
    PyObject* raw_target_name; /* capsule */
    PyObject* raw_cred = Py_None; /* capsule or default: None */
    PyObject* raw_ctx = Py_None; /* capsule or default: None */
    PyObject* raw_mech_type = Py_None; /* int or default: None */
    PyObject* flags_list = Py_None; /* list of ints, default: [MUTUAL, SEQUENCE] */
    OM_uint32 ttl = 0; /* default: 0 */
    PyObject* raw_channel_bindings = Py_None; /* capsule or default: None */
    char *raw_input_token = NULL; /* not null terminated, default: None/NuLL */
    int raw_input_token_len;

    static char *kwlist[] = {"target_name", "cred", "context", "mech_type", "flags", "time", "channel_bindings", "input_token", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, keywds, "O|OOOOIOs#", kwlist,
                                    &raw_target_name, &raw_cred, &raw_ctx,
                                    &raw_mech_type, &flags_list, &ttl,
                                    &raw_channel_bindings, &raw_input_token,
                                    &raw_input_token_len))
        return NULL;

    gss_name_t target_name = GET_CAPSULE(gss_name_t, raw_target_name);

    gss_cred_id_t cred = CAPSULE_OR_DEFAULT(gss_cred_id_t, raw_cred,
                                            GSS_C_NO_CREDENTIAL);

    gss_ctx_id_t ctx = CAPSULE_OR_DEFAULT(gss_ctx_id_t, raw_ctx,
                                          GSS_C_NO_CONTEXT);

    gss_OID mech_type = CAPSULE_OR_DEFAULT(gss_OID, raw_mech_type,
                                           GSS_C_NO_OID);

    OM_uint32 req_flags = parseFlags(flags_list,
                                    (GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG));

    gss_channel_bindings_t bdng = CAP_OR_DFLT_DR(gss_channel_bindings_t,
                                                 raw_channel_bindings,
                                                 GSS_C_NO_CHANNEL_BINDINGS);

    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;

    if (raw_input_token && *raw_input_token)
    {
        input_token.length = raw_input_token_len;
        input_token.value = raw_input_token;
    }

    gss_OID actual_mech_type;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 ret_flags;
    OM_uint32 output_ttl;

    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    Py_BEGIN_ALLOW_THREADS
        maj_stat = gss_init_sec_context(&min_stat, cred, &ctx, target_name,
                                        mech_type, req_flags, ttl, bdng,
                                        &input_token, &actual_mech_type,
                                        &output_token, &ret_flags,
                                        &output_ttl);
    Py_END_ALLOW_THREADS

    if (maj_stat == GSS_S_COMPLETE || maj_stat == GSS_S_CONTINUE_NEEDED) {
        PyObject *cap_ctx = PyCapsule_New(ctx, NULL, NULL);
        PyObject *cap_mech_type = createMechType(actual_mech_type);
        PyObject *reqs_out = createFlagsList(ret_flags);
        PyObject *continue_needed;
        if (maj_stat == GSS_S_CONTINUE_NEEDED) {
            continue_needed = Py_True;
            Py_INCREF(Py_True);
        }
        else {
            continue_needed = Py_False;
            Py_INCREF(Py_False);
        }

        PyObject *res = Py_BuildValue("OOOs#IO", cap_ctx, cap_mech_type,
                                      reqs_out, output_token.value,
                                      output_token.length, output_ttl,
                                      continue_needed);

        gss_release_buffer(&min_stat, &output_token);
        Py_DECREF(reqs_out);
        Py_DECREF(cap_ctx);
        Py_DECREF(cap_mech_type);
        Py_DECREF(continue_needed);
        return res;
    }
    else {
        raise_gss_error(maj_stat, min_stat);
        return NULL;
    }
}

#define INT_OR_DEFAULT(obj, def) VALUE_OR_DEFAULT(obj, PyInt_AsLong(obj), def)

static PyObject *
wrap(PyObject *self, PyObject *args)
{
    PyObject *raw_ctx;
    const char *message;
    int message_len;
    int conf_req = 1;
    PyObject *raw_qop = Py_None;

    if(!PyArg_ParseTuple(args, "Os#|iO", &raw_ctx, &message, &message_len,
                         &conf_req, &raw_qop))
        return NULL;

    OM_uint32 qop_req = INT_OR_DEFAULT(raw_qop, GSS_C_QOP_DEFAULT);

    gss_buffer_desc input_message_buffer = GSS_C_EMPTY_BUFFER;

    gss_ctx_id_t ctx = GET_CAPSULE_DEREF(gss_ctx_id_t, raw_ctx);

    input_message_buffer.length = message_len;
    input_message_buffer.value = message;

    gss_buffer_desc output_message_buffer = GSS_C_EMPTY_BUFFER;
    int conf_state;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    Py_BEGIN_ALLOW_THREADS
        maj_stat = gss_wrap(&min_stat, ctx, conf_req, qop_req,
                            &input_message_buffer, &conf_state,
                            &output_message_buffer);
    Py_END_ALLOW_THREADS

    if (maj_stat == GSS_S_COMPLETE) {
        PyObject *conf_state_out;
        if (conf_state) {
            conf_state_out = Py_True;
            Py_INCREF(Py_True);
        }
        else {
            conf_state_out = Py_False;
            Py_INCREF(Py_False);
        }

        PyObject *res = Py_BuildValue("s#O", output_message_buffer.value,
                                      output_message_buffer.length,
                                      conf_state_out);

        gss_release_buffer(&min_stat, &output_message_buffer);
        Py_DECREF(conf_state_out);
        return res;
    }
    else {
        raise_gss_error(maj_stat, min_stat);
        return NULL;
    }
}

static PyObject *
unwrap(PyObject *self, PyObject *args)
{
    PyObject *raw_ctx;
    const char *message;
    int message_len;

    if(!PyArg_ParseTuple(args, "Os#", &raw_ctx, &message, &message_len))
        return NULL;

    gss_buffer_desc input_message_buffer = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx = GET_CAPSULE_DEREF(gss_ctx_id_t, raw_ctx);

    input_message_buffer.length = message_len;
    input_message_buffer.value = message;

    gss_buffer_desc output_message_buffer = GSS_C_EMPTY_BUFFER;
    int conf_state;
    gss_qop_t qop_state;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    Py_BEGIN_ALLOW_THREADS
        maj_stat = gss_unwrap(&min_stat, ctx, &input_message_buffer,
                              &output_message_buffer, &conf_state, &qop_state);
    Py_END_ALLOW_THREADS

    if (maj_stat == GSS_S_COMPLETE)
    {
        PyObject *conf_state_out;
        if (conf_state) {
            conf_state_out = Py_True;
            Py_INCREF(Py_True);
        }
        else {
            conf_state_out = Py_False;
            Py_INCREF(Py_False);
        }

        PyObject *res = Py_BuildValue("s#OI", output_message_buffer.value,
                                      output_message_buffer.length,
                                      conf_state_out, qop_state);
        gss_release_buffer(&min_stat, &output_message_buffer);
        Py_DECREF(conf_state_out);
        return res;
    }
    else {
        raise_gss_error(maj_stat, min_stat);
        return NULL;
    }
}

static PyMethodDef GSSAPIMethods[] = {
    {"importName", importName, METH_VARARGS,
     "Convert a string name and type into a GSSAPI name object"},
    {"acquireCred", acquireCred, METH_VARARGS | METH_KEYWORDS,
     "Acquire credentials from a name object"},
    {"releaseName", releaseName, METH_VARARGS,
     "Release a GSSAPI name"},
    {"releaseCred", releaseCred, METH_VARARGS,
     "Release GSSAPI credentials"},
    {"initSecContext", initSecContext, METH_VARARGS | METH_KEYWORDS,
     "Initialize a GSS security context"},
    {"acceptSecContext", acceptSecContext, METH_VARARGS | METH_KEYWORDS,
     "Accept a GSS security context"},
    {"deleteSecContext", deleteSecContext, METH_VARARGS,
     "Release a GSS security context"},
    {"unwrap", unwrap, METH_VARARGS,
     "Unwrap and possibly decrypt a message"},
    {"wrap", wrap, METH_VARARGS,
     "Wrap and possibly encrypt a message"},
    {"getMechanismType", getMechanismType, METH_VARARGS,
     "convert a value from the MechType enum into a mechanism type for use with GSSAPI methods"},
    {NULL, NULL, 0, NULL} /* sentinel value */
};

PyMODINIT_FUNC
initimpl(void)
{
    Py_InitModule("gssapi.base.impl", GSSAPIMethods);

    PyObject *types_module = PyImport_ImportModule("gssapi.base.types");

        PyObject *gsserror_attr_name = PyString_FromString("GSSError");
        GSSError_class = PyObject_GetAttr(types_module, gsserror_attr_name);
        Py_DECREF(gsserror_attr_name); /* we don't need it any more */

        PyObject *requirementflag_attr_name = PyString_FromString("RequirementFlag");
        RequirementFlag_class = PyObject_GetAttr(types_module,
                                                 requirementflag_attr_name);
        Py_DECREF(requirementflag_attr_name); /* we don't need it any more */

        PyObject *mechtype_attr_name = PyString_FromString("MechType");
        MechType_class = PyObject_GetAttr(types_module, mechtype_attr_name);
        Py_DECREF(mechtype_attr_name); /* we don't need it any more */

    Py_DECREF(types_module); /* we don't need it any more */
}
