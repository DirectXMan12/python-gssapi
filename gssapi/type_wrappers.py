import gssapi.base as gss

is_string = None

try:
    is_string = lambda x: isinstance(x, basestring)
except NameError:
    is_string = lambda x: isinstance(x, str) or isinstance(x, bytes)

class GSSContext(gss.SecurityContext):
    def __new__(cls, base_ctx, *args, **kwargs):
        return super(GSSContext, cls).__new__(cls, base_ctx)

    def __init__(self, base_ctx, initiator, mech, token,
                 flags, ttl, delegated_credentials, continue_needed):
        self.initiator = initiator
        self.mech = mech
        self.token = token
        self.flags = flags
        self.ttl = ttl
        self.delegated_credentials = delegated_credentials
        self.continue_needed = continue_needed

    def accept(self, *args, **kwargs):
        """
        Accept updates to a security context

        Like :func:`GSSContext.accept_new`, but
        updates the current context in-place
        """

        res = type(self).accept_new(*args, context=self, **kwargs)
        self.initiator = res.initiator
        self.mech = res.mech
        self.token = res.token
        self.flags = res.flags
        self.ttl = res.ttl
        self.delegated_credentials = res.delegated_credentials
        self.continue_needed = res.continue_needed

        return self

    def initiate(self, *args, **kwargs):
        """
        Initiate updates to a security context.

        Like GSSContext.initiate_new, but updates the current
        context in-place.
        """

        res = type(self).accept_new(*args, context=self, **kwargs)
        self.mech = res.mech
        self.token = res.token
        self.flags = res.flags
        self.ttl = res.ttl
        self.continue_needed = res.continue_needed

        return self

    @classmethod
    def accept_new(cls, tok, acceptor_cred=None,
                   channel_bindings=None):
        """
        Accept a new security context

        This method accepts a new security context.
        Its parameters behave like those of
        :func:`gssapi.base.impl.acceptSecContext`
        except as noted here.

        :param cred: the acceptor credentials
        :type cred: GSSCredentials or None
        :returns: the newly accepted context
        :rtype: GSSContext
        """

        resp = gss.acceptSecContext(tok, acceptor_cred=acceptor_cred,
                                    channel_bindings=channel_bindings)

        return GSSContext(resp[0],
                          initiator=GSSName(base_name=resp[1]),
                          mech=resp[2],
                          token=resp[3],
                          flags=resp[4],
                          ttl=resp[5],
                          delegated_credentials=GSSCredentials(resp[6]),
                          continue_needed=resp[7])

    @classmethod
    def initiate_new(cls, name, cred=None, context=None,
                     mech_type=None, flags=None, ttl=0,
                     channel_bindings=None, input_token=None):

        resp = gss.initSecContext(name, input_token=input_token,
                                  mech_type=mech_type, flags=flags, ttl=ttl,
                                  channel_bindings=channel_bindings)

        return GSSContext(resp[0], mech=resp[1], flags=resp[2], token=resp[3],
                          ttl=resp[4], continue_needed=resp[5])


class GSSCredentials(gss.Creds):
    def __new__(cls, base_creds):
        return super(GSSCredentials, cls).__new__(cls, base_creds)

    def __init__(self, base_creds):
        # TODO(sross): use introspection methods
        #              to discover these
        self.ttl = 0
        self.mechs = None

    def impersonate(name, cred_usage='both', ttl=None,
                    mechs=None, reuse_mechs=True):
        """
        Use these credentials to impersonate a name
        
        This method returns a new set of credentials
        obtained by impersonating "name" using
        the current set of credentials.  All parameters
        behave like those of :func:`gssapi.base.impl.acquireCred`,
        except as noted here.

        :param GSSName name: the name to impersonate
        :param usage: the cred usage
        :type usage: 'both', 'initiate', 'accept'
        :param ttl: the TTL for the new credentials (or to
                    reuse the current credentials TTL)
        :type ttl: int or None
        :param bool reuse_mechs: reuse the current credentials' mechs?
                                 (True will override the 'mechs' param)
        :returns: a new set of impersonating credentials
        :rtype: GSSCredentials
        """

        if ttl is None:
            ttl = self.ttl

        if reuse_mechs:
            mechs = self.mechs

        resp = gss.acquireCredImpersonateName(self.capsule, name.capsule,
                                              cred_usage=cred_usage, ttl=ttl,
                                              mechs=mechs)
        res = GSSCredentials(resp[0])
        res.ttl = resp[2]
        res.mechs = resp[1]

        return res

    @classmethod
    def acquire(cls, name, cred_usage='both', ttl=0, mechs=None):
        """
        Acquire credentials for the given name

        This method acquires credentials for the given name.
        All parameters behave equivalently to those of
        :func:`gssapi.base.impl.acquireCred`, except as noted
        here.

        :param usage: the cred usage
        :type usage: 'both', 'initiate', 'accept'
        :returns: the acquired credentials
        :rtype: GSSCredentials
        """

        resp = gss.acquireCred(name, cred_usage=cred_usage,
                               ttl=ttl, mechs=mechs)

        res = cls(resp[0])
        res.ttl = resp[2]
        res.mechs = resp[1]

        return res

class GSSName(gss.Name):
    """
    A GSS Name Object

    This class represents a GSS name object, conviniently
    wrapping the underlying Capsule object and automatically
    freeing the name upon the object's destruction.  Also provides
    good str and repr values.
    """

    def __new__(cls, name=None, name_type=gss.NameType.hostbased_service,
                base_name=None):
        if base_name is None:
            base_res = gss.importName(name.encode('utf-8'), name_type)
        else:
            base_res = base_name

        return super(GSSName, cls).__new__(cls, base_res)

    def __init__(self, name=None, name_type=gss.NameType.hostbased_service,
                 base_name=None):
        """
        Creates a GSSName

        This method creates a GSS Name of the given type and value

        :param str name: the string part of the name
        :param name_type: the type of the name
        :type name_type: :class:`gssapi.base.types.NameType`
        """

        if base_name is not None and (name is None):
            displ_resp = gss.displayName(self)
            self.name_type = displ_resp[1]
            self.name = displ_resp[0].decode('utf-8')

        self.name_type = name_type
        self.name = name

    # del isn't needed, because __dealloc__ takes care of it for us

    @classmethod
    def create_if_needed(cls, *args, **kwargs):
        """
        Create a GSSName if needed, otherwise just return the object

        This utility method checks its arguments to see if the argument
        is already a GSSName.  If it is, we just return that.  Otherwise,
        we pass the parameters on to the constructor.
        """
        if len(args) + len(kwargs) > 1:
            # we have base inputs
            return cls(*args, **kwargs)

        obj = None
        try:
            obj = args[0]
        except IndexError:
            try:
                obj = kwargs['name']
            except KeyError:
                raise ValueError('No valid arguments were passed to'
                                 '{0}.create_or_wrap'.format(cls.__name__))

        if is_string(obj):
            return cls(obj)
        elif isinstance(obj, cls):
            return obj
        elif isinstance(obj, gss.Name):
            name, tp = gss.displayName(obj)
            return cls(name, tp, base_name=obj)

    def __str__(self):
        return "{0} ({1})".format(self.name, self.name_type)

    def __repr__(self):
        return "<gss name ({0}): {1} -- {2}>".format(self.name_type, self.name)

    def __eq__(self, target):
        return gss.compareName(self.capsule, target.capsule)

    def __deepcopy__(self, memo):
        cpy = gss.duplicateName(self)
        return type(self)(self.name, self.name_type, base_name=cpy)
