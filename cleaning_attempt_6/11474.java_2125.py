class ConstructState:
    def __init__(self, parent=None):
        self.parent = parent
        if parent is not None:
            parent.add_sub_state(self)

    @property
    def sub_states(self):
        return self._sub_states

    @sub_states.setter
    def add_sub_state(self, op_state):
        self._sub_states.append(op_state)

    @property
    def parent(self):
        return self.__parent

    @parent.setter
    def set_parent(self, value):
        self.__parent = value

    def get_sub_state(self, index):
        return self.sub_states[index]

    def compute_hashcode(self, hashcode=0x56c93c59):
        if not hasattr(self, 'ct') or self.ct is None:
            return hashcode
        id = getattr(self.ct, 'id', 0)
        hashcode ^= (id >> 8) & 0xff
        hashcode >>= 8

        for sub_state in self.sub_states:
            hashcode = sub_state.compute_hashcode(hashcode)

        return hashcode

    @property
    def constructor(self):
        return getattr(self, 'ct', None)

    @constructor.setter
    def set_constructor(self, value):
        setattr(self, 'ct', value)

    @property
    def length(self):
        return self.__length

    @length.setter
    def set_length(self, value):
        self.__length = value

    @property
    def offset(self):
        return self.__offset

    @offset.setter
    def set_offset(self, value):
        self.__offset = value

    def dump_constructor_tree(self):
        if not hasattr(self, 'ct') or self.ct is None:
            return None
        sb = StringBuilder()
        sb.append(str(getattr(self.ct, 'lineno', 0)))

        subs = []
        for cs in self.sub_states:
            s = cs.dump_constructor_tree()
            if s is not None:
                subs.append(s)

        if len(subs) == 0:
            return str(sb)
        sb.append('[')
        sb.append(','.join(map(str, subs)))
        sb.append(']')
        return str(sb)


class StringBuilder:
    def __init__(self):
        self.__str = ''

    @property
    def value(self):
        return self.__str

    def append(self, s):
        self.__str += str(s)

    def toString(self):
        return self.value


from functools import reduce
import itertools as it
import operator as op

def join(*args, sep=','):
    return sep.join(map(str, args))

class StringUtils:
    @staticmethod
    def join(iterable, sep=','):
        return sep.join(map(str, iterable))
