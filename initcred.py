#!/usr/bin/env python

import socket
from subprocess import call

fqdn = socket.getfqdn()
call('kinit host/'+fqdn+' -k', shell=True)
