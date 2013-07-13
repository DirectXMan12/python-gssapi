=====
TODOs
=====

Features
========

- implement the rest of the methods
  (see gssapi/base/impl.py)

- figure out if we can run unit tests
  not under sudo

Bugs
====

- Seg fault if we try to wrap before
  initializing a context with a server
  token

- figure out why after failing tests the credential
  cache seems to be cleared sometimes when running
  tests which fail
