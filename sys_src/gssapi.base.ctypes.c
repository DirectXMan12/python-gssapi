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

    PyDict_SetItemString(module_dict, "GSS_C_DELEG_FLAG", PyInt_FromLong(GSS_C_DELEG_FLAG));
    PyDict_SetItemString(module_dict, "GSS_C_MUTUAL_FLAG", PyInt_FromLong(GSS_C_MUTUAL_FLAG));
    PyDict_SetItemString(module_dict, "GSS_C_REPLAY_FLAG", PyInt_FromLong(GSS_C_REPLAY_FLAG));
    PyDict_SetItemString(module_dict, "GSS_C_SEQUENCE_FLAG", PyInt_FromLong(GSS_C_SEQUENCE_FLAG));
    PyDict_SetItemString(module_dict, "GSS_C_CONF_FLAG", PyInt_FromLong(GSS_C_CONF_FLAG));
    PyDict_SetItemString(module_dict, "GSS_C_INTEG_FLAG", PyInt_FromLong(GSS_C_INTEG_FLAG));
    PyDict_SetItemString(module_dict, "GSS_C_ANON_FLAG", PyInt_FromLong(GSS_C_ANON_FLAG));
    PyDict_SetItemString(module_dict, "GSS_C_TRANS_FLAG", PyInt_FromLong(GSS_C_TRANS_FLAG));
}
