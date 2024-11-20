import abc

class NessieExternalDatabase:
    def __init__(self, value):
        self.value = value

NessieExternalDatabase.__metaclass__ = type(
    'NessieExternalDatabaseMeta',
    (abc.ABCMeta,), {}
)
