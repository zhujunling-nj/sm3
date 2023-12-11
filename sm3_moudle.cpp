#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "sm3.h"

static PyObject *method_sm3_hash(PyObject *self, PyObject *args) {
    Py_buffer src;
    if (!PyArg_ParseTuple(args, "y*", &src)) {
        return NULL;
    }

    byte hash[32];
    sm3_hash(hash, (bytes)src.buf, src.len);
    PyBuffer_Release(&src);
    return PyBytes_FromStringAndSize((char *)hash, 32);
}

static PyObject *method_sm3_hmac(PyObject *self, PyObject *args) {
    Py_buffer key, src;
    if (!PyArg_ParseTuple(args, "y*y*", &key, &src)) {
        return NULL;
    }

    byte hmac[32];
    sm3_hmac(hmac, (bytes)key.buf, key.len, (bytes)src.buf, src.len);
    PyBuffer_Release(&key);
    PyBuffer_Release(&src);
    return PyBytes_FromStringAndSize((char *)hmac, 32);
}

static PyMethodDef SM3Methods[] = {
    {"sm3_hash", method_sm3_hash, METH_VARARGS, "SM3 Hash."},
    {"sm3_hmac", method_sm3_hmac, METH_VARARGS, "SM3 HMac."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef sm3module = {
    PyModuleDef_HEAD_INIT,
    "_sm3",
    "SM3 Hash.",
    -1,
    SM3Methods
};

PyMODINIT_FUNC PyInit__sm3(void) {
    return PyModule_Create(&sm3module);
}
