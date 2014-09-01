#include <Python.h>
#include "rtmpserver.h"


typedef struct
{
    PyObject_HEAD
    RTMPServer * server;
}
pexip_PexipObject;

static PyObject* pexrtmp_rtmp_server_start(pexip_PexipObject* self, PyObject* args)
{
    const char * application_name;
    int port;

    if (!PyArg_ParseTuple(args, "si", &application_name, &port)) {
        return NULL;
    }

    self->server = rtmp_server_new(application_name, port);
    if (self->server == NULL) {
        Py_RETURN_NONE;
    }
    return Py_BuildValue("s", "ready");
}

static PyObject* pexrtmp_rtmp_server_stop(pexip_PexipObject* self)
{
    if (self->server == NULL) {
        Py_RETURN_NONE;
    }
    rtmp_server_stop(self->server);
    rtmp_server_free(self->server);
    self->server = NULL;
    return Py_BuildValue("s", "stopped");
}

static PyMethodDef pexip_PexipObject_methods[] =
{
    {"start", (PyCFunction)pexrtmp_rtmp_server_start, METH_VARARGS, "start the rtmp server (application_name, port)"},
    {"stop", (PyCFunction)pexrtmp_rtmp_server_stop, METH_NOARGS, "stop the rtmp server"},
    { NULL, NULL, 0, NULL}
};


static PyTypeObject pexip_PexipType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "pexrtmpserver.RTMPServer",             /*tp_name*/
    sizeof(pexip_PexipObject), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    0,                         /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Pexip RTMP Server",          /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    pexip_PexipObject_methods, /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                         /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
    0,                         /* tp_free */
    0,                         /* tp_is_gc */
    0,                         /* tp_bases */
    0,                         /* tp_mro */
    0,                         /* tp_cache */
    0,                         /* tp_subclasses */
    0,                         /* tp_weaklist */
    0,                         /* tp_del */
    0,                         /* tp_version_tag */

};


#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif


static PyMethodDef pexip_module_methods[] =
{
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initpyrtmpserver(void)
{
    PyObject* m;

    pexip_PexipType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&pexip_PexipType) < 0)
        return;

    m = Py_InitModule3("pyrtmpserver", pexip_module_methods, "pyrtmpserver.");

    Py_INCREF(&pexip_PexipType);
    PyModule_AddObject(m, "pyrtmpserver", (PyObject*)&pexip_PexipType);
}
