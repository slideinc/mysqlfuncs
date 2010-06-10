/*
 * Copyright 2005-2010 Slide, Inc.
 * All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * Slide not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.
 *
 * SLIDE DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN
 * NO EVENT SHALL SLIDE BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <Python.h>
#include <netinet/in.h>
#if defined(__linux__)
	#include <byteswap.h>
	#include <endian.h>
#endif

#define MIN_FIELD_LEN 13

#define FLAG_NOT_NULL 0x01

static int _decode_pos_field_size[] = {
	-1, /* 0  catalog */
	-1, /* 1  db */
	-1, /* 2  table */
	-1, /* 3  org_table */
	-1, /* 4  name */
	-1, /* 5  org_name */
	 1, /* 6  (filler 1) */
	 2, /* 7  charset */
	 4, /* 8  length */
	 1, /* 9  type */
	 2, /* 10 flags */
	 1, /* 11 decimals */
	 1, /* 12 (filler 2) */
	 0 };

struct serial_buffer {
	char *buf;
	int   off;
	int   len;
	int   err;
};

#if defined(__linux__)
	#if __BYTE_ORDER == __LITTLE_ENDIAN
	#define mtohs(x)  (x)
	#define mtohl(x)  (x)
	#define mtohll(x) (x)
	#else
	#define mtohs(x)  bswap_16(x)
	#define mtohl(x)  bswap_32(x)
	#define mtohll(x) bswap_64(x)
	#endif
#elif defined(__APPLE__)
	#include <libkern/OSByteOrder.h>
	#define mtohs(x)  OSSwapLittleToHostInt16(x)
	#define mtohl(x)  OSSwapLittleToHostInt32(x)
	#define mtohll(x) OSSwapLittleToHostInt64(x)
#endif

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION == 4
typedef int Py_ssize_t ;
#endif

static int _check_size(struct serial_buffer *data, int space)
{
	if ((data->len - data->off) < space) {
		PyErr_SetString(PyExc_ValueError,
				"abnormal string termination");
		data->err = -EINVAL;
		return -EINVAL;
	}

	return 0;
}

static uint64_t unpack_len_internal(struct serial_buffer *data)
{
	uint8_t  snap;
	uint64_t value;

	if (_check_size(data, sizeof(uint8_t)))
		return 0;

	snap = *(uint8_t *)(data->buf+data->off);
	data->off += sizeof(uint8_t);	

	switch(snap) {
	case 251:
		value = 0;
		break;
	case 252:
		if (_check_size(data, sizeof(uint16_t)))
			return 0;

		value = mtohs(*(uint16_t *)(data->buf+data->off));
		data->off += sizeof(uint16_t);
		break;
	case 253:
		if (_check_size(data, sizeof(uint32_t)))
			return 0;

		value = mtohl(*(uint32_t *)(data->buf+data->off));
		data->off += sizeof(uint32_t);
		/*
		 * documentation says 32 bits, but wire decode shows 24 bits.
		 * (there is enough padding on the wire for 32, but lets stick
		 * to 24...) Rollover to 254 happens at 24 bit boundry.
		 */
		value &= 0xFFFFFF;
		break;
	case 254:
		if (_check_size(data, sizeof(uint64_t)))
			return 0;

		value = mtohll(*(uint64_t *)(data->buf+data->off));
		data->off += sizeof(uint64_t);
		break;
	default:
		value = snap;
		break;
	}

	return value;
}

static PyObject *unpack_field_internal(struct serial_buffer *d)
{
	PyObject *output = NULL;
	PyObject *item = NULL;
	int *pos = _decode_pos_field_size;
	int offset = 0;
	int result;
	int size;

	output = PyList_New(MIN_FIELD_LEN);
	if (!output)
		return NULL;

	while ((size = *pos++)) {
		if (size < 0) {
			size = unpack_len_internal(d);
			if (d->err)
				goto error;
		}

		if (_check_size(d, size))
		       goto error;

		switch (offset) {
		case 9: /* type */
			item = PyInt_FromLong((int32_t)(*(uint8_t *)(d->buf + d->off)));
			break;
		case 10: /* flags */
			item = PyInt_FromLong((int32_t)mtohs(*(uint16_t *)(d->buf + d->off)));
			break;
		default:
			item = PyString_FromStringAndSize((d->buf + d->off),
							  size);
			break;
		}

		if (!item)
			goto error;

		PyList_SET_ITEM(output, offset++, item);

		d->off += size;
	}
	/*
	 * 4.1 has an optional default field	
	 */
	if (d->off < d->len) {
		size = unpack_len_internal(d);
		if (d->err)
			goto error;

		if (_check_size(d, size))
		       goto error;

		item = PyString_FromStringAndSize((d->buf + d->off), size);
		if (!item)
			goto error;

		d->off += size;

		result = PyList_Append(output, item);
		Py_DECREF(item);
		if (result)
			goto error;
	}

	if (d->off < d->len)
		goto error;

	return output;
error:
	Py_DECREF(output);
	return NULL;
	
}

static PyObject *unpack_data_internal
(
	struct serial_buffer *d,
	PyObject *fields
)
{
	PyObject *type  = NULL;
	PyObject *flag  = NULL;
	PyObject *field = NULL;
	PyObject *output = NULL;
	PyObject *item = NULL;
	char *endptr;
	int result;
	int size;
	int pos = 0;
	
	output = PyList_New(0);
	if (!output)
		return NULL;

	while (d->off < d->len) {
		size = unpack_len_internal(d);
		if (d->err)
			goto error;

		if (_check_size(d, size))
		       goto error;

		field = PyList_GetItem(fields, pos++);
		if (!field) {
			PyErr_SetString(PyExc_ValueError, "no field in list");
			goto error;
		}

		if (!PyList_Check(field)) {
			PyErr_SetString(PyExc_TypeError, "bad type in list");
			goto error;
		}

		if (MIN_FIELD_LEN > PyList_GET_SIZE(field)) {
			PyErr_SetString(PyExc_TypeError, "field too short");
			goto error;
		}

		type = PyList_GET_ITEM(field, 9);
#if 0
		if (!PyInt_Check(type)) {
			PyErr_SetString(PyExc_TypeError,
					"field type not integer");
			goto error;
		}
#endif
		if (!size) {

			switch(PyInt_AS_LONG(type)) {
			default:
				flag = PyList_GET_ITEM(field, 10);

				if (PyInt_AS_LONG(flag) & FLAG_NOT_NULL)
					break;

				/* fall through */
			case 0x00: /* decimal */
			case 0x01: /* tiny */
			case 0x02: /* short */
			case 0x09: /* int24 */
			case 0x03: /* long */
			case 0x08: /* longlong */
				item = Py_None;
				Py_INCREF(item);
				break;
			}

			if (item)
				goto append;
		}


		switch(PyInt_AS_LONG(type)) {
		case 0x00: /* decimal */
		case 0x01: /* tiny */
		case 0x02: /* short */
		case 0x09: /* int24 */
			endptr = (d->buf + (d->off + size));
			item = PyInt_FromLong(strtol(d->buf + d->off,
						     &endptr,
						     10));
			break;
		case 0x03: /* long */
		case 0x08: /* longlong */
			item = PyLong_FromLongLong(strtoll(d->buf + d->off,
							   &endptr,
							   10));
			break;
		case 0x04: /* ,	_null_float,	'float'), */
		case 0x05: /* ,	_null_float,	'double'), */


		case 0x06: /* null */
		case 0x07: /* timestamp */
		case 0x0A: /* date */
		case 0x0B: /* time */
		case 0x0C: /* datetime */
		case 0x0D: /* year */
		case 0x0E: /* newdate */
		case 0x0F: /* varchar */ /* MySQL 5.0 */
		case 0x10: /* bit */ /* MySQL 5.0 */
		case 0xF6: /* newdecimal */ /* MySQL 5.0 */
		case 0xF7: /* enum */
		case 0xF8: /* set */
		case 0xF9: /* tiny_blob */
		case 0xFA: /* medium_blob */
		case 0xFB: /* long_blob */
		case 0xFC: /* blob */
		case 0xFD: /* var_string */
			/* in the C code it is VAR_STRING */
		case 0xFE: /* string */
		case 0xFF: /* geometry */
		default:
			item = PyString_FromStringAndSize((d->buf + d->off),
							  size);
			break;
		}

		if (!item)
			goto error;

		d->off += size;
append:
		result = PyList_Append(output, item);
		Py_DECREF(item);
		if (result)
			goto error;
	}

	return output;
error:
	Py_DECREF(output);
	return NULL;
	
}

static PyObject *rip_packets_internal(struct serial_buffer *d)
{
	PyObject *output = NULL;
	PyObject *packet = NULL;
	uint32_t size;
	uint32_t seq;
	int result;

	output = PyList_New(0);
	if (!output)
		return NULL;

	while (d->off < d->len) {
		if (sizeof(uint32_t) > (d->len - d->off))
			break;
		/*
		 * 3-byte length, one-byte packet number.
		 * followed by packet data
		 */
		size  = mtohl(*(uint32_t *)(d->buf + d->off));
		seq   = size >> 24;
		size &= 0xFFFFFF;

		d->off += sizeof(uint32_t);

		if (size > (d->len - d->off)) {
			d->off -= sizeof(uint32_t);
			break;
		}
		
		packet = PyString_FromStringAndSize((d->buf + d->off), size);
		if (!packet) {
			d->off -= sizeof(uint32_t);
			break;
		}

		result = PyList_Append(output, packet);
		Py_DECREF(packet);
		if (result) {
			d->off -= sizeof(uint32_t);
			break;
		}

		d->off += size;
	}

	return output;
}

static PyObject *py_unpack_field(PyObject *self, PyObject *args)
{
	struct serial_buffer buffer;
	PyObject *input;
	int result;

	result = PyArg_ParseTuple(args, "O!",
				  &PyString_Type, (PyObject *)&input);
	if (!result)
		return NULL;

	buffer.len = PyString_GET_SIZE(input);
	buffer.off = 0;
	buffer.err = 0;
	buffer.buf = PyString_AS_STRING(input);

	return unpack_field_internal(&buffer);
}

static PyObject *py_unpack_data(PyObject *self, PyObject *args)
{
	struct serial_buffer buffer;
	PyObject *input;
	PyObject *fields;
	int result;

	result = PyArg_ParseTuple(args, "O!O!",
				  &PyString_Type, (PyObject *)&input,
				  &PyList_Type, (PyObject *)&fields);
	if (!result)
		return NULL;

	buffer.len = PyString_GET_SIZE(input);
	buffer.off = 0;
	buffer.err = 0;
	buffer.buf = PyString_AS_STRING(input);

	return unpack_data_internal(&buffer, fields);
}

static PyObject *py_rip_packets(PyObject *self, PyObject *args)
{
	struct serial_buffer buffer;
	PyObject *input;
	PyObject *output;
	int result;

	result = PyArg_ParseTuple(args, "O!",
				  &PyString_Type, (PyObject *)&input);
	if (!result)
		return NULL;

	buffer.len = PyString_GET_SIZE(input);
	buffer.off = 0;
	buffer.err = 0;
	buffer.buf = PyString_AS_STRING(input);

	output = rip_packets_internal(&buffer);
	if (!output)
		return NULL;

	memcpy(PyString_AS_STRING(input),
	       (buffer.buf + buffer.off),
	       ((buffer.len - buffer.off) + 1));

	PyString_GET_SIZE(input) -= buffer.off;
	return output;
}

static PyMethodDef _myfun_methods[] = {
	{"unpack_field", py_unpack_field, METH_VARARGS,
	 "Unpack a mysql field response string."},
	{"unpack_data", py_unpack_data, METH_VARARGS,
	 "Unpack a mysql data response string."},
	{"rip_packets", py_rip_packets, METH_VARARGS,
	 "Given string of wire data, break it up into N packets."},
	{NULL, NULL, 0, NULL}
};


PyMODINIT_FUNC initmysqlfuncs(void)
{
	(void) Py_InitModule("mysqlfuncs", _myfun_methods);
}

/*
 * Local Variables:
 * c-file-style: "linux"
 * indent-tabs-mode: t
 * End:
 */
