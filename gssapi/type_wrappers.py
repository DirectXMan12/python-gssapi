import gssapi.base as gss

class GSSName(object):
    """
    A GSS Name Object

    This class represents a GSS name object, conviniently
    wrapping the underlying Capsule object and automatically
    freeing the name upon the object's destruction.  Also provides
    good str and repr values.
    """

    def __init__(self, name, name_type=gss.NameType.hostbased_service):
        """
        Creates a GSSName

        This method creates a GSS Name of the given type and value

        :param str name: the string part of the name
        :param name_type: the type of the name
        :type name_type: :class:`gssapi.base.types.NameType`
        """

        self.name_type = name_type
        self.name = name
        self.capsule = gss.importName(self.name, self.name_type)

    def __del__(self):
        gss.releaseName(self.capsule)

    def __str__(self):
        return "{0} ({1})".format(self.name, self.name_type)

    def __repr__(self):
        return "<gss name ({0}): {1}>".format(self.name_type, self.name)

