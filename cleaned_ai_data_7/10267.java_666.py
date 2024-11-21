import inspect
from collections import OrderedDict

class Beanify:
    @staticmethod
    def beanify(beany):
        result = OrderedDict()
        bclass = type(beany)
        methods = [method for method in inspect.getmembers(bclass, predicate=inspect.ismethod) if not method[0].startswith('__')]
        for name, method in methods:
            try:
                thing = method[1](beany)
                result[name] = thing
            except Exception as e:
                result[name] = str(e)

        fields = [field for field in inspect.getmembers(bclass) if isinstance(field[1], property)]
        for _, field in fields:
            try:
                thing = getattr(beany, field[0])
                result[field[0]] = thing
            except Exception as e:
                result[field[0]] = str(e)

        return result

    @staticmethod
    def fix(name):
        if name.startswith('get') and len(name) > 3:
            return name[3].lower() + name[4:]
        elif name.startswith('is') and len(name) > 2:
            return name[2].lower() + name[3:]
        else:
            return None
