class DataTypeComparator:
    def compare(self, o1: object, o2: object) -> int:
        if isinstance(o1, type) and isinstance(o2, type):
            dt1 = cast(type, o1)
            dt2 = cast(type, o2)

            name1 = dt1.name
            name2 = dt2.name

            # If the names are the same, then sort by the path            
            if name1.lower() == name2.lower():
                return (dt1.path_name).lower().compareTo((dt2.path_name).lower())

        elif isinstance(o1, str) and isinstance(o2, type):
            dt2 = cast(type, o2)
            name2 = dt2.name

            return o1.lower().compareTo(name2.lower())
        elif isinstance(o1, type) and isinstance(o2, str):
            dt1 = cast(type, o1)
            name1 = dt1.name

            return name1.lower().compareTo(o2.lower())

        return 0
