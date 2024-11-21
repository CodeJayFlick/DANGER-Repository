# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class BusinessException(Exception):
    pass


def business_operation(func: callable) -> callable:
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise BusinessException(str(e))
    return wrapper


BusinessOperation = type('BusinessOperation', (), {
    '__call__': lambda self, *args, **kwargs: self.perform()
})

class BusinessOperation(metaclass=BusinessOperation):
    def __init__(self):
        pass

    def perform(self) -> any:
        raise NotImplementedError
