#include <Python.h>
#include <gssapi.h>
#include "py_compat.h"

static PyObject *
displayStatus(PyObject *self, PyObject *args, PyObject *keywds)
{
    OM_uint32 err_code;
    int is_major_code; /* boolean */
    PyObject *raw_mech_type = Py_None; /* capsule or default: None */
    OM_uint32 message_context = 0; /* default: 0 */

    static char *kwlist[] = {"err_code", "is_major_code", "mech_type", "message_context", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "Ii|OI", kwlist,
                                     &err_code, &is_major_code,
                                     &raw_mech_type, &message_context))
        return NULL;

    int status_type;
    gss_OID mech_type;

    if (is_major_code)
        status_type = GSS_C_GSS_CODE;
    else
        status_type = GSS_C_MECH_CODE;

    if (raw_mech_type == Py_None)
        mech_type = GSS_C_NO_OID;
    else
        mech_type = *((gss_OID *)PyCapsule_GetPointer(raw_mech_type, NULL));

    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    OM_uint32 msg_ctx_out = message_context;
    gss_buffer_desc msg_buff;

    maj_stat = gss_display_status(&min_stat, err_code, status_type, mech_type,
                                  &msg_ctx_out, &msg_buff);


    if (maj_stat == GSS_S_COMPLETE) {
        PyObject *call_again;
        if (msg_ctx_out) {
            call_again = Py_True;
            Py_INCREF(Py_True);
        }
        else {
            call_again = Py_False;
            Py_INCREF(Py_False);
        }
        PyObject *res = Py_BuildValue("s#IO", msg_buff.value, msg_buff.length,
                                      msg_ctx_out, call_again);
        gss_release_buffer(&min_stat, &msg_buff);
        Py_DECREF(call_again);
        return res;
    }
    else {
        gss_release_buffer(&min_stat, &msg_buff);
        Py_RETURN_NONE;
    }
}

static PyMethodDef StatusUtilsMethods[] = {
    {"displayStatus", displayStatus, METH_VARARGS | METH_KEYWORDS,
     "Turn GSSAPI status codes into human-readable strings"},
    {NULL, NULL, 0, NULL} /* sentinel value */
};

MOD_INIT(status_utils)
{
    PyObject *module;
    DEFINE_MODULE_STATELESS(module, "gssapi.base.status_utils",
                            StatusUtilsMethods);

    return MOD_SUCCESS(module);
}
