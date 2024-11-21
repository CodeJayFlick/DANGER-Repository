class ContextDatabase:
    def __init__(self):
        pass

    def dispose(self):
        pass

    def get_context_size(self):
        raise NotImplementedError("Method not implemented")

    def register_variable(self, nm: str, sbit: int, ebit: int) -> None:
        raise NotImplementedError("Method not implemented")

    def get_variable(self, nm: str) -> 'ContextBitRange':
        raise NotImplementedError("Method not implemented")

    def get_region(self, res: list[int], addr1: Address, addr2: Address) -> None:
        raise NotImplementedError("Method not implemented")

    def getContext(self, addr: Address):
        raise NotImplementedError("Method not implemented")

    def getContext(self, addr: Address, first: int, last: int):
        raise NotImplementedError("Method not implemented")

    def get_default_value(self) -> list[int]:
        raise NotImplementedError("Method not implemented")

    def create_context(self, addr: Address) -> list[int]:
        raise NotImplementedError("Method not implemented")

    def get_tracked_default(self) -> 'VectorSTL[TrackedContext]':
        raise NotImplementedError("Method not implemented")

    def get_tracked_set(self, addr: Address) -> 'VectorSTL[TrackedContext]':
        raise NotImplementedError("Method not implemented")

    def create_set(self, addr1: Address, addr2: Address) -> 'VectorSTL[TrackedContext]':
        raise NotImplementedError("Method not implemented")

    def save_xml(self, s):
        pass

    def restore_xml(self, el: Element, translate: Translate):
        pass

    def restore_from_spec(self, el: Element, translate: Translate):
        pass

    def save_tracked(self, s, addr: Address, vec: 'VectorSTL[TrackedContext]'):
        if not vec:
            return
        s.write("<tracked_pointset>\n")
        addr.get_space().save_xml_attributes(s, addr.get_offset())
        s.write(">\n")
        for i in range(len(vec)):
            s.write("   ")
            vec[i].save_xml(s)
        s.write("</tracked_pointset>\n")

    def set_variable_default(self, nm: str, val: int):
        var = self.get_variable(nm)
        var.set_value(self.get_default_value(), val)

    def get_default_value(self, nm: str) -> int:
        var = self.get_variable(nm)
        return var.get_value(self.get_default_value())

    def set_variable(self, nm: str, addr: Address, value: int):
        bitrange = self.get_variable(nm)
        new_context = self.create_context(addr)
        bitrange.set_value(new_context, value)

    def get_variable(self, nm: str, addr: Address) -> int:
        bitrange = self.get_variable(nm)
        context = self.getContext(addr)
        return bitrange.get_value(context)

    def set_context_range(self, addr: Address, num: int, mask: int, value: int):
        new_context = self.create_context(addr)
        val = new_context[num]
        val &= ~mask
        val |= value
        new_context[num] = val

    def set_variable_region(self, nm: str, begad: Address, endad: Address, value: int):
        bitrange = self.get_variable(nm)
        vec = []
        self.get_region(vec, begad, endad)
        for i in range(len(vec)):
            bitrange.set_value(vec[i], value)

    def get_tracked_value(self, mem: 'VarnodeData', point: Address) -> int:
        tset = self.get_tracked_set(point)
        endoff = mem.offset + mem.size - 1
        tendoff = None
        for i in range(len(tset)):
            tcont = tset[i]
            if tcont is None:
                tcont = TrackedContext()
                tset.set(i, tcont)

            # tcont must contain -mem-
            if tcont.loc.space != mem.space or tcont.loc.offset > mem.offset:
                continue
            tendoff = tcont.loc.offset + tcont.loc.size - 1
            if tendoff < endoff:
                continue

            res = tcont.val
            # If we have proper containment, trim value based on endianness
            if tcont.loc.space.is_big_endian():
                if endoff != tendoff:
                    res >>= (8 * (tendoff - mem.offset))
            else:
                if mem.offset != tcont.loc.offset:
                    res >>= (8 * (mem.offset - tcont.loc.offset))

            res &= Utils.calc_mask(mem.size)
            return res
        return 0

    @staticmethod
    def restore_tracked(el: Element, trans: Translate, vec: 'VectorSTL[TrackedContext]'):
        vec.clear()
        list = el.get_children()
        iter = list.iterator()

        while iter.has_next():
            subel = next(iter)
            vec.push_back(TrackedContext())
            vec.back().restore_xml(subel, trans)

    class TrackedContext:
        def __init__(self):
            pass

        def restore_xml(self, el: Element, translate: Translate) -> None:
            raise NotImplementedError("Method not implemented")

        @property
        def loc(self):
            return self._loc

        @loc.setter
        def loc(self, value):
            self._loc = value

        @property
        def val(self):
            return self._val

        @val.setter
        def val(self, value):
            self._val = value


class Address:
    def __init__(self):
        pass

    def get_space(self) -> 'Space':
        raise NotImplementedError("Method not implemented")

    def get_offset(self) -> int:
        raise NotImplementedError("Method not implemented")


class Space:
    def __init__(self):
        pass

    @property
    def is_big_endian(self):
        return self._is_big_endian

    @is_big_endian.setter
    def is_big_endian(self, value):
        self._is_big_endian = value


def main():
    # Example usage of the ContextDatabase class.
    db = ContextDatabase()
    print(db.get_context_size())  # This will raise a NotImplementedError.


if __name__ == "__main__":
    main()

