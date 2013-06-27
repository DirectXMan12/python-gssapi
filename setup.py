#!/usr/bin/env python2.7
from distutils.core import setup
from distutils.core import Extension
import sys
import commands

long_desc = """
This package provides an Object-Oriented python wrapper around the
GSSAPI C libraries.
"""

ext_module_b = Extension(
    'gssapi.base.impl',
    extra_link_args = commands.getoutput('krb5-config --libs gssapi').split(),
    extra_compile_args = commands.getoutput('krb5-config --cflags gssapi').split(),
    sources = [
        'sys_src/gssapi.base.impl.c'
    ]
)

ext_module_ct = Extension(
    'gssapi.base.ctypes',
    extra_link_args = commands.getoutput('krb5-config --libs gssapi').split(),
    extra_compile_args = commands.getoutput('krb5-config --cflags gssapi').split(),
    sources = [
        'sys_src/gssapi.base.ctypes.c'
    ]
)

setup(
    name='PyGSSAPI',
    version='0.0.1',
    author='Solly Ross',
    author_email='sross@redhat.com',
    packages=['gssapi', 'gssapi.test', 'gssapi.base'],
    description='Python GSSAPI Wrapper',
    long_description=long_desc,
    license='LICENSE.txt',
    ext_modules = [ext_module_b, ext_module_ct]
)

