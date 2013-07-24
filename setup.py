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
    def _get_output(*args, **kwargs):
        res = subprocess.check_output(*args, shell=True, **kwargs)
        decoded = res.decode('utf-8')
        return decoded.strip()

    get_output = _get_output

ext_module_b = Extension(
    'gssapi.base.impl',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
#   include_dirs=['/home/sross/pydebug/include/python2.7'],
    include_dirs=['./sys_src'],
    sources = [
        'sys_src/gssapi.base.impl.c'
    ]
)

ext_module_ct = Extension(
    'gssapi.base.ctypes',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
#   include_dirs=['/home/sross/pydebug/include/python2.7'],
    include_dirs=['./sys_src'],
    sources = [
        'sys_src/gssapi.base.ctypes.c'
    ]
)

ext_module_su = Extension(
    'gssapi.base.status_utils',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
#   include_dirs=['/home/sross/pydebug/include/python2.7'],
    include_dirs=['./sys_src'],
    sources = [
        'sys_src/gssapi.base.status_utils.c'
    ]
)

setup(
    name='PyGSSAPI',
    version='1.0.0',
    author='Solly Ross',
    author_email='sross@redhat.com',
    packages=['gssapi', 'gssapi.base', 'gssapi.tests'],
    description='Python GSSAPI Wrapper',
    long_description=open('README.txt').read(),
    license='LICENSE.txt',
    url="https://github.com/directxman12/python-gssapi",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Security'
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    ext_modules = [ext_module_b, ext_module_ct, ext_module_su],
    install_requires=[
        'flufl.enum >= 4.0'
    ],
    tests_require=[
        'tox'
    ]
)
