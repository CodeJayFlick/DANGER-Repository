Here is the translation of the Java code to Python:
```
class PathNotExistException(Exception):
    PATH_NOT_EXIST_WRONG_MESSAGE = "Path [%s] does not exist"

    def __init__(self, path):
        super().__init__(self.PATH_NOT_EXIST_WRONG_MESSAGE % (path,), TSStatusCode.TIMESERIES_NOT_EXIST)
    
    def __init__(self, path, is_user_exception=False):
        super().__init__(self.PATH_NOT_EXIST_WRONG_MESSAGE % (path,), TSStatusCode.TIMESERIES_NOT_EXIST, is_user_exception)

    @classmethod
    def from_paths(cls, paths):
        if len(paths) == 1:
            message = self.PATH_NOT_EXIST_WRONG_MESSAGE % (paths[0],)
        else:
            message = self.PATH_NOT_EXIST_WRONG_MESSAGE % (paths[0] + " ... " + paths[-1],)
        super().__init__(message, TSStatusCode.TIMESERIES_NOT_EXIST)

class TSStatusCode:
    TIMESERIES_NOT_EXIST = 123
```
Note that I had to create a separate `TSStatusCode` class in Python since there is no direct equivalent of Java's enum type. In this implementation, the values are just integers.

Also, I used the `%` operator for string formatting, which is similar to how it was done in Java.