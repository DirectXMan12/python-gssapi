#include <Python.h>
#include <gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <stdio.h>

#define DEBUG(mn, str, args...) printf("  %s: " str "\n", mn, args)

PyObject *GSSError_class;

static void raise_gss_error(OM_uint32 maj, OM_uint32 min)
{
    //PyErr_SetObject(GssException_class, Py_BuildValue("((s:i)(s:i))", buf_maj, err_maj, buf_min, err_min));
    //printf("gss error %d %d\n", maj, min);
    PyErr_SetObject(GSSError_class, Py_BuildValue("II", maj, min));
}

static PyObject *
importName(PyObject *self, PyObject *args)
{
    const char *name;  
    int name_len;
    int raw_name_type = 0; // default to hostbased_service

    if(!PyArg_ParseTuple(args, "s#|i", &name, &name_len, &raw_name_type))
        return NULL;

    // do stuff
    gss_OID name_type;
    switch(raw_name_type)
    {
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
            // TODO(sross): throw error
            break;
    }

    gss_buffer_desc name_token = GSS_C_EMPTY_BUFFER;
    name_token.length = name_len;
    name_token.value = name;

    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    gss_name_t output_name;

    Py_BEGIN_ALLOW_THREADS
      maj_stat = gss_import_name(&min_stat, &name_token, name_type, &output_name);
    Py_END_ALLOW_THREADS

    if (maj_stat == GSS_S_COMPLETE)
    {
        // return a capsule

        PyObject *out_name_obj = PyCapsule_New(output_name, NULL, NULL);
        return Py_BuildValue("O", out_name_obj);
    }
    else
    {
        raise_gss_error(maj_stat, min_stat);        
        return NULL;
    }
}

static PyObject *
releaseName(PyObject *self, PyObject *args)
{
    PyObject *name_obj;

    if (!PyArg_ParseTuple(args, "O", &name_obj))
        return NULL;
    
    gss_name_t name = (gss_name_t)PyCapsule_GetPointer(name_obj, NULL);

    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    maj_stat = gss_release_name(&min_stat, &name);

    if (maj_stat == GSS_S_COMPLETE)
    {
        Py_RETURN_NONE;
    }
    else
    {
       raise_gss_error(maj_stat, min_stat);
       return NULL;
    }
}

static PyObject *
deleteSecContext(PyObject *self, PyObject *args)
{
    PyObject *raw_context; // capsule
    int output_needed = 0; // boolean, default: False

    if(!PyArg_ParseTuple(args, "O|i", &raw_context, &output_needed))
        return NULL;

    gss_ctx_id_t ctx = (gss_ctx_id_t)PyCapsule_GetPointer(raw_context, NULL); 

    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    
    if (output_needed)
    {
        maj_stat = gss_delete_sec_context(&min_stat, &ctx, &output_token);
    }
    else
    {
        maj_stat = gss_delete_sec_context(&min_stat, &ctx, GSS_C_NO_BUFFER);
    }
        

    if (maj_stat == GSS_S_COMPLETE)
    {
        if (output_needed)
        {
            PyObject *res = Py_BuildValue("s#", output_token.value, output_token.length);
            gss_release_buffer(&min_stat, &output_token);
            return res;
        }
        else
        {
            Py_RETURN_NONE;
        }
    }
    else
    {
        raise_gss_error(maj_stat, min_stat);
        return NULL;
    }
}

static PyObject *
getMechanismType(PyObject *self, PyObject *args)
{
    int raw_mech_type;
    
    if (!PyArg_ParseTuple(args, "i", &raw_mech_type))
        return NULL;

    gss_OID mech_type;
    
    switch (raw_mech_type)
    {
        case 0:
            mech_type = gss_mech_krb5;
            break;
        default:
            // TODO(sross): raise exception
            mech_type = GSS_C_NO_OID;
            break;
    }

    return Py_BuildValue("O", PyCapsule_New(mech_type, NULL, NULL));
}


static PyObject *
initSecContext(PyObject *self, PyObject *args, PyObject *keywds)
{
    PyObject* raw_target_name; // capsule
    PyObject* raw_cred = Py_None; // capsule or default: None
    PyObject* raw_ctx = Py_None; // capsule or default: None
    PyObject* raw_mech_type = Py_None; // int or default: None
    PyObject* services_list = Py_None; // list of ints, default: [MUTUAL, SEQUENCE]
    OM_uint32 ttl = 0; // default: 0
    PyObject* raw_channel_bindings = Py_None; // capsule or default: None
    char *raw_input_token = NULL; // not null terminated, default: None/NuLL
    int raw_input_token_len; 

    static char *kwlist[] = {"target_name", "cred", "context", "mech_type", "services", "time", "channel_bindings", "input_token", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, keywds, "O|OOOOIOs#", kwlist, &raw_target_name, &raw_cred, &raw_ctx, &raw_mech_type, &services_list, &ttl, &raw_channel_bindings, &raw_input_token, &raw_input_token_len))
        return NULL;

    gss_name_t target_name = (gss_name_t)PyCapsule_GetPointer(raw_target_name, NULL);
    gss_cred_id_t cred;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_OID mech_type;
    OM_uint32 req_flags = 0;
    gss_channel_bindings_t input_chan_bindings;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;

    gss_OID actual_mech_type;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 ret_flags;
    OM_uint32 output_ttl;

    if (raw_cred == Py_None)
        cred = GSS_C_NO_CREDENTIAL; 
    else
        cred = (gss_cred_id_t)PyCapsule_GetPointer(raw_cred, NULL);

    if (raw_ctx == Py_None)
        ctx = GSS_C_NO_CONTEXT;
    else
        ctx = (gss_ctx_id_t)PyCapsule_GetPointer(raw_ctx, NULL);

    if (raw_mech_type == Py_None)
        mech_type = GSS_C_NO_OID;
    else
        mech_type = (gss_OID)PyCapsule_GetPointer(raw_mech_type, NULL);
    
    // deal with flags
    if (services_list == Py_None)
    {
        req_flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG;
    }
    else
    {
        int i;
        for (i = 0; i < PyList_Size(services_list); i++)
        {
            PyObject *raw_item = PyList_GetItem(services_list, i);
            int flag = PyInt_AsLong(PyNumber_Int(raw_item));
            req_flags = req_flags | flag;
        }
    }

    if (raw_channel_bindings == Py_None)
        input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS; 
    else
        input_chan_bindings = *((gss_channel_bindings_t*)PyCapsule_GetPointer(raw_channel_bindings, NULL));

    if (raw_input_token && *raw_input_token)
    {
        input_token.length = raw_input_token_len;
        input_token.value = raw_input_token;
    }

    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    Py_BEGIN_ALLOW_THREADS
      maj_stat = gss_init_sec_context(&min_stat, cred, &ctx, target_name, mech_type, req_flags, ttl, input_chan_bindings, &input_token, &actual_mech_type, &output_token, &ret_flags, &output_ttl);
    Py_END_ALLOW_THREADS

    if (maj_stat == GSS_S_COMPLETE || maj_stat == GSS_S_CONTINUE_NEEDED)
    {
        PyObject *cap_ctx = PyCapsule_New(ctx, NULL, NULL);
        PyObject *cap_mech_type = Py_None; // TODO(sross): figure out how to instantiate this from the code
        PyObject *reqs_out = PyList_New(0); // TODO(sross): actually test for each flag and add it
        int raw_continue_needed = maj_stat == GSS_S_CONTINUE_NEEDED;
        PyObject *continue_needed;
        if (raw_continue_needed)
        {
            continue_needed = Py_True;
            Py_INCREF(Py_True);
        }
        else
        {
            continue_needed = Py_False;
            Py_INCREF(Py_False);
        }

        PyObject *res = Py_BuildValue("OOOs#IO", cap_ctx, cap_mech_type, reqs_out, output_token.value, output_token.length, output_ttl, continue_needed);
        gss_release_buffer(&min_stat, &output_token);
        return res;

    }
    else
    {
        raise_gss_error(maj_stat, min_stat);
        return NULL;
    }
}
        
static PyObject *
wrap(PyObject *self, PyObject *args)
{
    PyObject *raw_ctx; 
    const char *message;
    int message_len;
    int conf_req;
    PyObject *raw_qop;
    OM_uint32 qop_req;

    if(!PyArg_ParseTuple(args, "Os#|iO", &raw_ctx, &message, &message_len, &conf_req, &raw_qop))
        return NULL;
    
    if (raw_qop == Py_None)
        qop_req = GSS_C_QOP_DEFAULT;
    else
        qop_req = PyInt_AsLong(raw_qop);

    gss_buffer_desc input_message_buffer = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx = *((gss_ctx_id_t *)PyCapsule_GetPointer(raw_ctx, NULL));

    input_message_buffer.length = message_len;
    input_message_buffer.value = message;
    
    gss_buffer_desc output_message_buffer = GSS_C_EMPTY_BUFFER;
    int conf_state;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    Py_BEGIN_ALLOW_THREADS
        maj_stat = gss_wrap(&min_stat, ctx, conf_req, qop_req, &input_message_buffer, &conf_state, &output_message_buffer);
    Py_END_ALLOW_THREADS

    if (maj_stat == GSS_S_COMPLETE)
    {
        PyObject *conf_state_out;
        if (conf_state)
        {
            conf_state_out = Py_True;
            Py_INCREF(Py_True);
        }
        else
        {
            conf_state_out = Py_False;
            Py_INCREF(Py_False);
        }

        PyObject *res = Py_BuildValue("s#O", output_message_buffer.value, output_message_buffer.length, conf_state_out);
        gss_release_buffer(&min_stat, &output_message_buffer);
        return res;
    }
    else
    {
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
    gss_ctx_id_t ctx = *((gss_ctx_id_t*)PyCapsule_GetPointer(raw_ctx, NULL));

    input_message_buffer.length = message_len;
    input_message_buffer.value = message;
    
    gss_buffer_desc output_message_buffer = GSS_C_EMPTY_BUFFER;
    int conf_state;
    gss_qop_t qop_state;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    Py_BEGIN_ALLOW_THREADS
        maj_stat = gss_unwrap(&min_stat, ctx, &input_message_buffer, &output_message_buffer, &conf_state, &qop_state);
    Py_END_ALLOW_THREADS

    if (maj_stat == GSS_S_COMPLETE)
    {
        PyObject *conf_state_out;
        if (conf_state)
        {
            conf_state_out = Py_True;
            Py_INCREF(Py_True);
        }
        else
        {
            conf_state_out = Py_False;
            Py_INCREF(Py_False);
        }

        PyObject *res = Py_BuildValue("s#OI", output_message_buffer.value, output_message_buffer.length, conf_state_out, qop_state);
        gss_release_buffer(&min_stat, &output_message_buffer);    
        return res;
    }
    else
    {
        raise_gss_error(maj_stat, min_stat);
        return NULL;
    }
}

static PyMethodDef GSSAPIMethods[] = {
    {"importName", importName, METH_VARARGS,
     "Convert a string name and type into a GSSAPI name object"},
    {"releaseName", releaseName, METH_VARARGS,
     "Release a GSSAPI name"},
    {"initSecContext", initSecContext, METH_VARARGS | METH_KEYWORDS,
     "Initialize a GSS security context"},
    {"deleteSecContext", deleteSecContext, METH_VARARGS,
     "Release a GSS security context"},
    {"unwrap", unwrap, METH_VARARGS,
     "Unwrap and possibly decrypt a message"},
    {"wrap", wrap, METH_VARARGS,
     "Wrap and possibly encrypt a message"},
    {"getMechanismType", getMechanismType, METH_VARARGS,
     "convert a value from the MechType enum into a mechanism type for use with GSSAPI methods"},
    {NULL, NULL, 0, NULL} // sentinel value
};

PyMODINIT_FUNC
initimpl(void)
{
    Py_InitModule("gssapi.base.impl", GSSAPIMethods);

    PyObject *types_module = PyImport_ImportModule("gssapi.base.types");
    PyObject *gsserror_attr_name = PyString_FromString("GSSError");
    GSSError_class = PyObject_GetAttr(types_module, gsserror_attr_name);
    Py_DECREF(types_module); // we don't need it any more
    Py_DECREF(gsserror_attr_name); // we don't need it any more
}
