class ObjectOrientedClassLayout:
    MEMBERS_ONLY = ("Legacy",)
    BASIC_SIMPLE_COMPLEX = ("Complex with Basic Fallback",)
    SIMPLE_COMPLEX = ("Complex with Simple Fallback",)
    COMPLEX = ("Complex Always",)

    def __str__(self):
        return self.label

ObjectOrientedClassLayout.__init__ = lambda self, label: setattr(self, 'label', label)
