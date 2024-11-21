Here is the translation of the Java code into Python:

```Python
class Comparators:
    def __init__(self):
        pass

comparators = []

def register_comparator(t1: type, t2: type, c: 'Comparator'):
    if t1 == object and t2 == object:
        raise ValueError("You must not add a comparator for Objects")
    comparators.append((t1, t2, c))

@staticmethod
def compare(o1: object, o2: object) -> int:
    if o1 is None or o2 is None:
        return 0

    c = get_comparator(type(o1), type(o2))
    
    if c is None:
        return 0
    
    return c.compare(o1, o2)

@staticmethod
def get_java_comparator():
    pass

comparators_quick_access = {}

def get_comparator(f: type, s: type) -> 'Comparator':
    p = (f, s)
    
    if p in comparators_quick_access:
        return comparators_quick_access[p]
    
    comp = get_comparator_i(f, s)
    comparators_quick_access[p] = comp
    return comp

def get_comparator_i(f: type, s: type) -> 'Comparator':
    for info in comparators:
        if issubclass(info[1], f) and issubclass(f, info[0]):
            return info[2]
        
        elif issubclass(s, f) and issubclass(f, info[0]):
            return InverseComparator(info[2])
    
    if s == f and not (s == object or f == object):
        return Comparator.equals_comparator
    
    c1 = None
    c2 = None

    for info in comparators:
        true_false = [True, False]
        
        for first in true_false:
            if issubclass(info[0], f) and issubclass(f, info[first]):
                c2 = Converters.get_converter(s, info[1 - first])
                if c2 is not None:
                    return first and ConvertedComparator(c1 or Converter(), info[2]) or InverseConvertedComparator(Converter() or info[2], c1)
            
            elif issubclass(info[0], s) and issubclass(s, info[first]):
                c1 = Converters.get_converter(f, info[1 - first])
                if c1 is not None:
                    return not first and ConvertedComparator(c1, info[2]) or InverseConvertedComparator(Converter() or info[2], c1)
    
    for info in comparators:
        true_false = [True, False]
        
        for first in true_false:
            c1 = Converters.get_converter(f, info[first])
            c2 = Converters.get_converter(s, info[1 - first])
            
            if c1 is not None and c2 is not None:
                return first and ConvertedComparator(c1, info[2], c2) or InverseConvertedComparator(Converter() or info[2], c1)
    
    return None

class ConvertedComparator:
    def __init__(self, c: 'Comparator', c1: 'Converter' = None, c2: 'Converter' = None):
        self.c = c
        self.c1 = c1
        self.c2 = c2
    
    def compare(self, o1: object, o2: object) -> int:
        if self.c1 is not None and (o1 is None or o2 is None):
            return 0
        
        t1 = self.c1.convert(o1)
        
        if t1 is None:
            return 0
        
        t2 = self.c2.convert(o2)
        
        if t2 is None:
            return 0
        
        return self.c.compare(t1, t2)

    def supports_ordering(self) -> bool:
        return self.c.supports_ordering()

    def __str__(self):
        return f"ConvertedComparator({self.c1}, {self.c}, {self.c2})"

class InverseConvertedComparator(ConvertedComparator):
    pass

class ConvertedComparator(ConvertedComparator):
    pass
```

Note: This translation is not perfect, as Python does not support Java's type system and annotations. The code may need to be adjusted based on the actual use case in your application.