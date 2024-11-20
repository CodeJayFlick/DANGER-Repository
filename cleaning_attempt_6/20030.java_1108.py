class Yggdrasil:
    MAGIC_NUMBER = 0x59676700
    LATEST_VERSION = 1

    def __init__(self):
        self.version = None
        self.class_resolvers = []
        self.field_handlers = []

    def new_output_stream(self, out):
        return DefaultYggdrasilOutputStream(self, out)

    def new_input_stream(self, in_):
        return DefaultYggdrasilInputStream(self, in_)

    def register_class_resolver(self, r):
        if not self.class_resolvers.__contains__(r):
            self.class_resolvers.append(r)

    def get_serializer(self, c):
        for r in self.class_resolvers:
            if isinstance(r, YggdrasilSerializer) and r.get_id(c) is not None:
                return r
        return None

    def get_class(self, id_):
        try:
            return Object.__class__
        except Exception as e:
            raise StreamCorruptedException("No class found for ID " + str(id_))

    @staticmethod
    def get_id(f):
        yid = f.getAnnotation(YggdrasilID)
        if yid is not None:
            return yid.value()
        else:
            return "" + f.getName()

    @staticmethod
    def get_enum_constant(c, id_):
        try:
            fields = c.getDeclaredFields()
            for field in fields:
                if Yggdrasil.get_id(field) == id_:
                    return Enum.valueOf(c, field.getName())
            raise StreamCorruptedException("Enum constant " + str(id_) + " does not exist in " + str(c))
        except Exception as e:
            raise StreamCorruptedException(str(e))

    def excessive_field(self, o, f):
        for h in self.field_handlers:
            if h.excessive_field(o, f):
                return
        raise StreamCorruptedException("Excessive field " + Yggdrasil.get_id(f) + " in class " + str(o.__class__) + " was not handled")

    def missing_field(self, o, f):
        for h in self.field_handlers:
            if h.missing_field(o, f):
                return
        raise StreamCorruptedException("Missing field " + Yggdrasil.get_id(f) + " in class " + str(o.__class__) + " was not handled")

    def incompatible_field(self, o, f, field_context):
        for h in self.field_handlers:
            if h.incompatible_field(o, f, field_context):
                return
        raise StreamCorruptedException("Incompatible field " + Yggdrasil.get_id(f) + " in class " + str(o.__class__) + " of incompatible " + str(field_context.type()) + " was not handled")

    def save_to_file(self, o, f):
        try:
            with open(str(f), 'wb') as fo:
                yout = self.new_output_stream(fo)
                yout.write_object(o)
                yout.flush()
        except Exception as e:
            raise IOException("Error writing to file " + str(f))

    def load_from_file(self, f, expected_type):
        try:
            with open(str(f), 'rb') as fi:
                yin = self.new_input_stream(fi)
                return yin.read_object(expected_type)
        except Exception as e:
            raise IOException("Error reading from file " + str(f))

    def new_instance(self, c):
        s = self.get_serializer(c)
        if s is not None and not s.can_be_instantiated(c):
            try:
                s.deserialize(c, Fields(self))
            except StreamCorruptedException as e:
                pass
            return None
        elif s is not None:
            o = s.new_instance(c)
            if o is None:
                raise YggdrasilException("YggdrasilSerializer " + str(s) + " returned null from new_instance(" + str(c) + ")")
            return o
        else:
            try:
                constr = c.getDeclaredConstructor()
                constr.setAccessible(True)
                return constr.newInstance()
            except Exception as e:
                raise StreamCorruptedException("Cannot create an instance of " + str(c) + " because it has no nullary constructor")

    @staticmethod
    def main(args):
        print("Command line not supported yet")
        exit(1)

class DefaultYggdrasilOutputStream(YggdrasilOutputStream):

    def __init__(self, yggdrasil, out):
        super().__init__()
        self.yggdrasil = yggdrasil
        self.out = out

    def write_object(self, o):
        pass  # TODO implement this method

class DefaultYggdrasilInputStream(YggdrasilInputStream):

    def __init__(self, yggdrasil, in_):
        super().__init__()
        self.yggdrasil = yggdrasil
        self.in_ = in_

    def read_object(self, expected_type):
        pass  # TODO implement this method

class YggdrasilID:

    @staticmethod
    def value():
        return None

class Fields(YggdrasilSerializable):

    def __init__(self, yggdrasil):
        super().__init__()
        self.yggdrasil = yggdrasil

    def get_type(self):
        pass  # TODO implement this method

class YggdrasilSerializer:

    @staticmethod
    def can_be_instantiated(c):
        return True

    def new_instance(self, c):
        pass  # TODO implement this method

    def deserialize(self, c, field_context):
        pass  # TODO implement this method

class StreamCorruptedException(Exception):

    pass

class YggdrasilException(Exception):

    pass
