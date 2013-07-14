#!/usr/bin/env python2.7
import setuptools
from setuptools import setup
from setuptools import Extension
import sys

get_output = None

try:
    import commands
    get_output = commands.getoutput
except ImportError:
    import subprocess
    get_output = lambda *a: subprocess.check_output(*a, shell=True)

ext_module_b = Extension(
    'gssapi.base.impl',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
#   include_dirs=['/home/sross/pydebug/include/python2.7'],
    sources = [
        'sys_src/gssapi.base.impl.c'
    ]
)

ext_module_ct = Extension(
    'gssapi.base.ctypes',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
#   include_dirs=['/home/sross/pydebug/include/python2.7'],
    sources = [
        'sys_src/gssapi.base.ctypes.c'
    ]
)

ext_module_su = Extension(
    'gssapi.base.status_utils',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
#   include_dirs=['/home/sross/pydebug/include/python2.7'],
    sources = [
        'sys_src/gssapi.base.status_utils.c'
    ]
)

setup(
    name='PyGSSAPI',
    version='0.1.0',
    author='Solly Ross',
    author_email='sross@redhat.com',
    packages=['gssapi', 'gssapi.base', 'gssapi.tests'],
    description='Python GSSAPI Wrapper',
    long_description=open('README.txt').read(),
    license='LICENSE.txt',
    ext_modules = [ext_module_b, ext_module_ct, ext_module_su],
    install_requires=[
        'flufl.enum >= 4.0'
    ],
    tests_require=[
        'tox'
    ]
)
