/* Python <2.7 / 3.0 capsule simulation using COjbect */
#include "capsulethunk.h"

#ifndef __PY_COMPAT_H
#define __PY_COMPAT_H

/* Python 3 compat: no more "Int" functions,
 * only "Long" functions */
#if PY_MAJOR_VERSION >= 3
#define PyInt_FromLong PyLong_FromLong
#define PyInt_AsLong PyLong_AsLong
#define PyNumber_Int PyNumber_Long
#endif

/* Python 3 compat: PyString_ methods don't exist
 * any more, use PyUnicode_ instead */
#if PY_MAJOR_VERSION >= 3
#define PyString_FromString PyUnicode_FromString
#endif

/* we reall want y# in Python 3
 * instead of s# when building a value */
#if PY_MAJOR_VERSION >= 3
#define BYTE_TUPLE_STR(a,b) (a "y#" b)
#define BYTE_STR "y#"
#else
#define BYTE_TUPLE_STR(a,b) (a "s#" b)
#define BYTE_STR "s#"
#endif

/* generic python 3 flag */
#if PY_MAJOR_VERSION >= 3
#define PY3K
#endif

/* Python 3 Module Init Helpers */

#if PY_MAJOR_VERSION >=3
#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))
#define STATESTUB

#define DEFINE_MODULE(obj, name, methods, clear, traverse, module_state) \
    static struct PyModuleDef moduledef = { \
        PyModuleDef_HEAD_INIT, \
        name, \
        NULL, /* doc */\
        sizeof(module_state), \
        methods, \
        NULL, /* reload */\
        traverse, /*traverse (for module_state)*/\
        clear, /*clear (for module_state(*/\
        NULL, /*free*/\
    }; \
    obj = PyModule_Create(&moduledef);

#define DEFINE_MODULE_STATELESS(obj, name, methods) \
    static struct PyModuleDef moduledef = { \
        PyModuleDef_HEAD_INIT, \
        name, \
        NULL, /* doc */\
        -1, \
        methods, \
        NULL, /* reload */\
        NULL, /*traverse (for module_state)*/\
        NULL, /*clear (for module_state(*/\
        NULL, /*free*/\
    }; \
    obj = PyModule_Create(&moduledef);

#define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)

#define MOD_SUCCESS(m) m

#else
#define GETSTATE(m) (&_state)
#define STATESTUB static struct module_state _state

#define DEFINE_MODULE(obj, name, methods, clear, traverse, module_state) \
    obj = Py_InitModule(name, methods)

#define DEFINE_MODULE_STATELESS(obj, name, methods) \
    obj = Py_InitModule(name, methods)

#define MOD_INIT(name) PyMODINIT_FUNC init##name(void)

#define MOD_SUCCESS(m)

#endif

#endif
