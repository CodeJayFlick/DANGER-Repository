class DefaultColumnComparator:
    def compare(self, o1: object, o2: object) -> int:
        if o1 is None or o2 is None:
            return TableComparators.compare_with_null_values(o1, o2)

        c1 = type(o1)
        c2 = type(o2)
        if isinstance(c1, str) and isinstance(c2, str):
            return self.compare_as_strings(o1, o2)

        if Comparable in [c1.__class__, c2.__class__]:
            comparable = Comparable(o1)
            result = comparable.compareTo(o2)
            return result

        # At this point we do not know how to compare these items well.  Return 0, which 
        # will signal to any further comparators that more comparing is needed.
        return 0

    def compare_as_strings(self, o1: object, o2: object) -> int:
        s1 = str(o1)
        s2 = str(o2)
        return s1.casefold().compare(s2.casefold())
