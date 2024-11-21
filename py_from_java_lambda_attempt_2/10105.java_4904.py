Here is the translation of the Java code into Python:

```Python
import datetime

class ItemCheckoutStatus:
    serialVersionUID = 1L
    VERSION = 3

    def __init__(self, checkout_id: int, checkout_type: str, user: str, version: int,
                 time: float, project_path: str):
        self.checkout_id = checkout_id
        self.checkout_type = checkout_type
        self.user = user
        self.version = version
        self.time = time
        if project_path is not None:
            project_path = project_path.replace('\\', '/')
        self.project_path = project_path

    def write_object(self, out):
        out.write_int(VERSION)
        out.write_long(self.checkout_id)
        out.write_string(self.user)
        out.write_int(self.version)
        out.write_float(self.time)
        out.write_int(ord(self.checkout_type))
        if self.project_path is not None:
            out.write_string(self.project_path)
        else:
            out.write_string('')

    def read_object(self, in):
        ver = in.read_int()
        if ver > self.VERSION:
            raise Exception("Unsupported version of ItemCheckoutStatus")
        self.checkout_id = in.read_long()
        self.user = in.read_string()
        self.version = in.read_int()
        self.time = in.read_float()
        if ver < 3:
            checkout_type_bool = in.read_boolean()
            self.checkout_type = 'EXCLUSIVE' if checkout_type_bool else 'NORMAL'
        else:  # Transient checkout added with Version 3
            checkout_type_id = in.read_int()
            self.checkout_type = get_checkout_type(checkout_type_id)
            if self.checkout_type is None:
                raise Exception("Invalid ItemCheckoutStatus Type: " + str(checkout_type_id))
        if ver > 1:  # Client project path added with Version 2
            self.project_path = in.read_string()
            if len(self.project_path) == 0:
                self.project_path = None

    def get_checkout_id(self):
        return self.checkout_id

    def get_checkout_type(self):
        return self.checkout_type

    def get_user(self):
        return self.user

    def get_checkout_version(self):
        return self.version

    def get_checkout_time(self):
        return self.time

    def get_checkout_date(self):
        return datetime.datetime.fromtimestamp(self.time)

    def get_project_path(self):
        return self.project_path

    def get_project_name(self):
        if self.project_path is None:
            return None
        path = self.project_path
        ix = path.rfind('/')
        if ix < 0:
            return None
        return path[ix + 1:]

    def get_project_location(self):
        if self.project_path is None:
            return None
        path = self.project_path
        ix = path.find('::')
        if ix > 0:
            path = path[ix + 2:]
        else:
            return None
        return path[:ix]

    def get_user_host_name(self):
        if self.project_path is None:
            return None
        ix = self.project_path.find('::')
        if ix > 0:
            return self.project_path[:ix]
        return None

def get_checkout_type(checkout_type_id: int) -> str:
    # This function should be implemented based on the actual implementation in Java.
    pass


class ObjectInputStream:
    def read_int(self):
        raise NotImplementedError()

    def read_long(self):
        raise NotImplementedError()

    def read_string(self):
        raise NotImplementedError()

    def read_float(self):
        raise NotImplementedError()

    def read_boolean(self):
        raise NotImplementedError()


def write_object(out, obj):
    out.write_int(3)
    out.write_long(obj.checkout_id)
    out.write_string(obj.user)
    out.write_int(obj.version)
    out.write_float(obj.time)
    out.write_int(ord(obj.checkout_type))
    if obj.project_path is not None:
        out.write_string(obj.project_path)
    else:
        out.write_string('')


def read_object(in):
    ver = in.read_int()
    if ver > 3:
        raise Exception("Unsupported version of ItemCheckoutStatus")
    checkout_id = in.read_long()
    user = in.read_string()
    version = in.read_int()
    time = in.read_float()
    checkout_type_bool = in.read_boolean()
    checkout_type = 'EXCLUSIVE' if checkout_type_bool else 'NORMAL'
    project_path = in.read_string() if ver > 1 else ''
    return ItemCheckoutStatus(checkout_id, checkout_type, user, version, time, project_path)
```

Please note that the Python code does not exactly match the Java code. The `write_object` and `read_object` methods are simplified as they were quite complex in the original Java code.