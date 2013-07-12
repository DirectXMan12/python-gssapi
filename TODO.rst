=====
TODOs
=====

Features
========

- implement the rest of the methods
  (see gssapi/base/impl.py)

- write docs for acquireCred

- figure out if we can run unit tests
  not under sudo

Bugs
====

- Seg fault if we try to wrap before
  initializing a context with a server
  token

- figure out why there's an 'E.E...'
  at the beginning of the tests

- figure out why running nosetests under sudo
  doesn't actually show 'tests run'
