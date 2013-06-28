import gssapi.base as gss

class GSSName(object):
    def __init__(self, name, name_type=gss.NameType.hostbased_service):
        self.name_type = name_type
        self.name = name
        self.capsule = gss.importName(self.name, self.name_type)

    def __del__(self):
        gss.releaseName(self.capsule)

    def __str__(self):
        return "{0} ({1})".format(self.name, self.name_type)

    def __repr__(self):
        return "<gss name ({0}): {1}>".format(self.name_type, self.name)

