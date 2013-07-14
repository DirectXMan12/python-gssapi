#include <Python.h>
#include <gssapi.h>

static PyMethodDef CTypesMethods[] = {
    {NULL, NULL, 0, NULL} // sentinel value
};

PyMODINIT_FUNC
initctypes(void)
{
    PyObject *module, *module_dict;

    module = Py_InitModule("gssapi.base.ctypes", CTypesMethods);

    PyObject *DELEG = PyInt_FromLong(GSS_C_DELEG_FLAG);
    PyObject *MUTUAL = PyInt_FromLong(GSS_C_MUTUAL_FLAG);
    PyObject *REPLAY = PyInt_FromLong(GSS_C_REPLAY_FLAG);
    PyObject *SEQUENCE = PyInt_FromLong(GSS_C_SEQUENCE_FLAG);
    PyObject *CONF = PyInt_FromLong(GSS_C_CONF_FLAG);
    PyObject *INTEG = PyInt_FromLong(GSS_C_INTEG_FLAG);
    PyObject *ANON = PyInt_FromLong(GSS_C_ANON_FLAG);
    PyObject *TRANS = PyInt_FromLong(GSS_C_TRANS_FLAG);

    PyModule_AddObject(module, "GSS_C_DELEG_FLAG", DELEG);
    PyModule_AddObject(module, "GSS_C_MUTUAL_FLAG", MUTUAL);
    PyModule_AddObject(module, "GSS_C_REPLAY_FLAG", REPLAY);
    PyModule_AddObject(module, "GSS_C_SEQUENCE_FLAG", SEQUENCE);
    PyModule_AddObject(module, "GSS_C_CONF_FLAG", CONF);
    PyModule_AddObject(module, "GSS_C_INTEG_FLAG", INTEG);
    PyModule_AddObject(module, "GSS_C_ANON_FLAG", ANON);
    PyModule_AddObject(module, "GSS_C_TRANS_FLAG", TRANS);
}
