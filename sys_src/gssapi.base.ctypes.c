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

    module_dict = PyModule_GetDict(module);

    PyObject *DELEG = PyInt_FromLong(GSS_C_DELEG_FLAG);
    PyObject *MUTUAL = PyInt_FromLong(GSS_C_MUTUAL_FLAG);
    PyObject *REPLAY = PyInt_FromLong(GSS_C_REPLAY_FLAG);
    PyObject *SEQUENCE = PyInt_FromLong(GSS_C_SEQUENCE_FLAG);
    PyObject *CONF = PyInt_FromLong(GSS_C_CONF_FLAG);
    PyObject *INTEG = PyInt_FromLong(GSS_C_INTEG_FLAG);
    PyObject *ANON = PyInt_FromLong(GSS_C_ANON_FLAG);
    PyObject *TRANS = PyInt_FromLong(GSS_C_TRANS_FLAG);

    PyDict_SetItemString(module_dict, "GSS_C_DELEG_FLAG", DELEG);
    PyDict_SetItemString(module_dict, "GSS_C_MUTUAL_FLAG", MUTUAL);
    PyDict_SetItemString(module_dict, "GSS_C_REPLAY_FLAG", REPLAY);
    PyDict_SetItemString(module_dict, "GSS_C_SEQUENCE_FLAG", SEQUENCE);
    PyDict_SetItemString(module_dict, "GSS_C_CONF_FLAG", CONF);
    PyDict_SetItemString(module_dict, "GSS_C_INTEG_FLAG", INTEG);
    PyDict_SetItemString(module_dict, "GSS_C_ANON_FLAG", ANON);
    PyDict_SetItemString(module_dict, "GSS_C_TRANS_FLAG", TRANS);

    Py_DECREF(DELEG);
    Py_DECREF(MUTUAL);
    Py_DECREF(REPLAY);
    Py_DECREF(SEQUENCE);
    Py_DECREF(CONF);
    Py_DECREF(INTEG);
    Py_DECREF(ANON);
    Py_DECREF(TRANS);

    Py_DECREF(module);
    Py_DECREF(module_dict);
}
