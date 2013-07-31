import gssapi.base as gss


class GSSName(gss.Name):
    """
    A GSS Name Object

    This class represents a GSS name object, conviniently
    wrapping the underlying Capsule object and automatically
    freeing the name upon the object's destruction.  Also provides
    good str and repr values.
    """

    @staticmethod
    def __new__(cls, name, name_type=gss.NameType.hostbased_service,
                base_name=None):
        if base_name is None:
            base_res = gss.importName(name.encode('utf-8'), name_type)
        else:
            base_res = base_name

        return super(GSSName, cls).__new__(cls, base_res)

    def __init__(self, name, name_type=gss.NameType.hostbased_service,
                 base_name=None):
        """
        Creates a GSSName

        This method creates a GSS Name of the given type and value

        :param str name: the string part of the name
        :param name_type: the type of the name
        :type name_type: :class:`gssapi.base.types.NameType`
        """

        self.name_type = name_type
        self.name = name

    # del isn't needed, because __dealloc__ takes care of it for us

    def __str__(self):
        return "{0} ({1})".format(self.name, self.name_type)

    def __repr__(self):
        return "<gss name ({0}): {1} -- {2}>".format(self.name_type, self.name)

    def __eq__(self, target):
        return gss.compareName(self.capsule, target.capsule)

    def __deepcopy__(self, memo):
        cpy = gss.duplicateName(self)
        return type(self)(self.name, self.name_type, base_name=cpy)
