class JREFieldHandler:
    def excessive_field(self, o, field):
        return False

    def missing_field(self, o, field):
        return False

    def incompatible_field(self, o, f, field) -> bool:
        value = field.get_object()
        if isinstance(value, list):
            value = [value]
        elif isinstance(value, collections.Collection):
            v = value
            try:
                if issubclass(f.get_type(), collections.abc.Collection):
                    c = f.get(o)
                    if c is not None:
                        c.clear()
                        c.update(v)
                        return True
                elif Object.__class__.is_subclass__(f.get_type(), list):
                    array = f.get(o) or []
                    if len(array) < v.size():
                        return False
                    ct = array[0].__class__
                    for x in v:
                        if not isinstance(x, ct):
                            return False
                    while len(array) < v.size():
                        array.append(None)
                else:
                    f.set(o, [x for x in v])
            except (AttributeError, TypeError, ValueError):
                raise YggdrasilException()
        elif isinstance(value, dict):
            if not issubclass(f.get_type(), dict):
                return False
            try:
                m = f.get(o) or {}
                if m is not None:
                    m.clear()
                    m.update(value)
                    return True
            except (AttributeError, TypeError, ValueError):
                raise YggdrasilException()

    def __init__(self):
        pass

class YggdrasilException(Exception):
    pass
