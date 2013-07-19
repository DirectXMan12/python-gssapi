========
PyGSSAPI
========

PyGSSAPI provides both low-level and high level wrappers around the GSSAPI
C libraries.  While it focuses on the Kerberos mechanism, it should also be
useable with other GSSAPI mechanisms that do not rely on mechanism-specific
C values that cannot easily be translated into Python.

Requirements
============

* A working implementation of GSSAPI (such as from MIT Kerberos)
  which includes header files

* a C compiler (such as GCC)

* the `flufl.enum` Python package

* the `nose` package (for tests)

* the `shouldbe` package (for tests)

Installation
============

Easy Way 
--------

.. code-block:: bash

    $ pip install py-gssapi

From the Git Repo
-----------------

.. code-block:: bash

    $ git clone https://github.com/DirectXMan12/python-gssapi.git
    $ python setup.py build
    $ python setup.py install

Tests
=====

I have written some tests of PyGSSAPI; they live in the `gssapi.tests`
directory.  Currently the basic `gssapi.base` commands have been tested.
Before running the tests, a valid 'host/[FQDN]' (e.g. 'host/sross.localdomain')
must have been `kinit`-ed.  If you run `tox`, it will do this for you (you will
likely need to run `tox` with `sudo`).  Additionally, a normal kerberos user
should also have been `kinit`-ed

.. code-block:: bash

   $ sudo kinit some_user
   $ sudo tox

or 

.. code-block:: bash
   
   $ sudo kinit host/some.domain -k
   $ sudo kinit some_user
   $ sudo nosetests

Structure
=========

PyGSSAPI is composed of two parts: the low-level, C-style wrapper and the
high-level, Python-style wrapper (which is a wrapper around the low-level
API).  Modules written in C are denoted by '(C)', whereas those written
in Python are denoted '(Py)'

Low-Level API
-------------

The low-level API lives in `gssapi.base`.  The methods contained therein
are designed to match closely with the original GSSAPI C methods.  They
follow the given format:

* Names are camelCased versions of the C method names, with the 'gssapi_'
  prefix removed

* Parameters which use C int constants as enums have `flufl.enum` IntEnums
  defined, and thus may be passed either the enum members or integers

* In cases where a specific constant is passed in the C API to represent
  a default value, `None` should be passed instead

* In cases where non-integer C constants are passed, `flufl.enum` Enums
  are defined for common values

* Major and minor error codes are returned via GSSErrors

* All other relevant output values are returned in a tuple in the return
  value of the method (in cases where a non-error major status code may
  be returned, an additional member of the tuple is provided)

Structure
~~~~~~~~~

gssapi : /
    base : /
        *includes all sub-packages automatically*

        impl : (C)
            core C-API methods
        status_utils : (C)
            utilities for dealing with status codes
        types : (Py)
            Enumerations and Exception Types

Examples
~~~~~~~~

.. code-block:: python

    import gssapi.base as gb

TODO(sross): provide more examples

High-Level API
--------------

The high-level API lives directly under `gssapi`.  The classes contained
in each file are designed to provide a more Python, Object-Oriented view
of GSSAPI.  Currently, they are designed for the basic GSSAPI tasks, but
will be expanded upon in the future.

Structure
~~~~~~~~~

gssapi : /
    client : (Py)
        *basic clients*

        BasicGSSClient
            a client capable of performing basic GSS negotiation/encryption
        BasicSASLGSSClient
            a helper class to simplify working with SASL GSSAPI
    type_wrappers : (Py)
        provides useful wrappers around some Python capsule objects

Examples
~~~~~~~~

.. code-block:: python

    import gssapi.client as gss
    
    client = gss.BasicGSSClient('vnc@some.host', security_type='encrypted')

    init_token = client.setupBaseSecurityContext()
    # send to server, get response back...
    next_token = client.updateSecurityContext(server_resp)
    # encrypt a message
    msg_enc = client.encrypt('WARNING: this is secret')
    # send the message, get response back...
    msg_unenc = client.decrypt(server_encrypted_message)

    # freeing of resources (such as deleting the security context and releasing
    # the names) is handled automatically
