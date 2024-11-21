import serializable

class IExpression(metaclass=serializable.Serializable):
    def get_type(self) -> str:
        pass  # implement this method in your subclass

    def clone(self) -> 'IExpression':
        raise NotImplementedError("Must be implemented by subclasses")
