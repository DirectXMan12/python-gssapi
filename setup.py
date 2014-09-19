#!/usr/bin/env python
from setuptools import setup
from setuptools.extension import Extension
from Cython.Distutils import build_ext
import sys
import re

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

ext_module_misc = Extension(
    'gssapi.base.misc',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
    sources = [
        'gssapi/base/misc.pyx',
#        'gssapi/base/cython_converters.pyx'
    ]
)

ext_module_creds = Extension(
    'gssapi.base.creds',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
    sources = [
        'gssapi/base/creds.pyx',
#        'gssapi/base/cython_converters.pyx'
    ]
)

ext_module_s4u = Extension(
    'gssapi.base.s4u',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
    sources = [
        'gssapi/base/s4u.pyx',
    ]
)

ext_module_names = Extension(
    'gssapi.base.names',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
    sources = [
        'gssapi/base/names.pyx',
#        'gssapi/base/cython_converters.pyx'
    ]
)

ext_module_sec_contexts = Extension(
    'gssapi.base.sec_contexts',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
    sources = [
        'gssapi/base/sec_contexts.pyx',
#        'gssapi/base/cython_converters.pyx'
    ]
)

ext_module_types = Extension(
    'gssapi.base.types',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
    sources = [
        'gssapi/base/types.pyx',
#        'gssapi/base/cython_converters.pyx'
    ]
)

ext_module_message = Extension(
    'gssapi.base.message',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
    sources = [
        'gssapi/base/message.pyx',
#        'gssapi/base/cython_converters.pyx'
    ]
)

ext_module_cython_converters = Extension(
    'gssapi.base.cython_converters',
    extra_link_args = get_output('krb5-config --libs gssapi').split(),
    extra_compile_args = get_output('krb5-config --cflags gssapi').split(),
    sources = [
        'gssapi/base/cython_converters.pyx',
#        'gssapi/base/cython_converters.pyx'
    ]
)

long_desc = re.sub('\.\. role:: \w+\(code\)\s*\n\s*.+', '',
                   re.sub(r':(python|bash|code):', '',
                          re.sub(r'\.\. code-block:: \w+', '::',
                                 open('README.txt').read())))

setup(
    name='PyGSSAPI',
    version='1.0.0',
    author='Solly Ross',
    author_email='sross@redhat.com',
    packages=['gssapi', 'gssapi.base', 'gssapi.tests'],
    description='Python GSSAPI Wrapper',
    long_description=long_desc,
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
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    cmdclass = {'build_ext': build_ext},
    ext_modules = [
        ext_module_misc,
        ext_module_creds,
        ext_module_names,
        ext_module_sec_contexts,
        ext_module_types,
        ext_module_message,
        ext_module_cython_converters,
        ext_module_s4u,
    ],
    install_requires=[
        'flufl.enum >= 4.0'
    ],
    tests_require=[
        'tox'
    ]
)
