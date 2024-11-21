Here is the translation of the Java code into Python:

```Python
class VarnodeBank:
    def __init__(self):
        self.loc_tree = sorted(set(), key=lambda x: (x.address, x.size))

    class LocComparator:
        def compare(self, v1, v2):
            cmp = v1.address - v2.address
            if cmp != 0:
                return cmp
            if v1.size != v2.size:
                return 1 if v1.size < v2.size else -1
            if not v1.is_input and v2.is_input:
                return -1
            if not v2.is_input and v1.is_input:
                return 1
            if v1.def is None and v2.def is None:
                return 0
            if v1.def is None:
                return -1
            if v2.def is None:
                return 1
            return (v1.def.seqnum - v2.def.seqnum).cmp

    class DefComparator:
        def compare(self, v1, v2):
            cmp = v1.is_input - v2.is_input
            if cmp != 0:
                return cmp
            comp = v1.address - v2.address
            if comp != 0:
                return comp
            if v1.size != v2.size:
                return 1 if v1.size < v2.size else -1
            if not v1.is_free and v2.is_free:
                return -1
            if not v2.is_free and v1.is_free:
                return 1
            comp = (v1.unique_id - v2.unique_id).cmp
            if comp != 0:
                return comp

    def clear(self):
        self.loc_tree.clear()

    @property
    def size(self):
        return len(self.loc_tree)

    @property
    def empty(self):
        return not bool(self.loc_tree)

    def create(self, s, addr, id):
        vn = VarnodeAST(addr, s, id)
        self.loc_tree.add(vn)
        return vn

    def destroy(self, vn):
        if vn in self.loc_tree:
            self.loc_tree.remove(vn)

    @property
    def loc_range(self):
        return iter(self.loc_tree)

    def make_free(self, vn):
        if vn in self.loc_tree:
            self.loc_tree.remove(vn)
            vn.def = None
            vn.is_input = False
            vn.is_free = True
            self.loc_tree.add(vn)

    @property
    def loc_range_spaceid(self, space_id):
        search_vn1 = VarnodeAST(space_id.address(0), 0, 0)
        search_vn2 = VarnodeAST(space_id.max_address(), int.MaxValue, 0)
        return iter(self.loc_tree).filter(lambda x: (x.address >= search_vn1.address) and (x.address <= search_vn2.address))

    def loc_range_addr(self, addr):
        search_vn1 = VarnodeAST(addr, 0, 0)
        search_vn2 = VarnodeAST(addr.add(1), 0, 0)
        return iter(self.loc_tree).filter(lambda x: (x.address >= search_vn1.address) and (x.address <= search_vn2.address))

    def loc_range_sz_addr(self, sz, addr):
        search_vn1 = VarnodeAST(addr, sz, 0)
        search_vn2 = VarnodeAST(addr, sz + 1, 0)
        return iter(self.loc_tree).filter(lambda x: (x.size == sz) and ((x.address >= search_vn1.address) and (x.address <= search_vn2.address)))

    def find(self, sz, addr, pc, uniq):
        if uniq == -1:
            uniq = 0
        op = PcodeOpAST(pc, uniq, PcodeOp.COPY, 0)
        iter = self.loc_tree.filter(lambda x: (x.size == sz) and (x.address == addr)).filter(lambda x: x.def is not None).filter(lambda x: x.def.seqnum.target() == pc)
        for vn in iter:
            if uniq != -1 or vn.def.seqnum.time() == uniq:
                return vn
        return None

    def find_input(self, sz, addr):
        search_vn = VarnodeAST(addr, sz, 0)
        search_vn.is_input = True
        iter = self.loc_tree.filter(lambda x: (x.size == sz) and (x.address == addr)).filter(lambda x: x.is_input)
        for vn in iter:
            return vn
        return None

class VarnodeAST:
    def __init__(self, address, size, unique_id):
        self.address = address
        self.size = size
        self.unique_id = unique_id
        self.def = None
        self.is_input = False
        self.is_free = True

    @property
    def get_address(self):
        return self.address

    @property
    def get_size(self):
        return self.size

    @property
    def get_unique_id(self):
        return self.unique_id

    @property
    def is_input(self):
        return self.is_input

    @is_input.setter
    def is_input(self, value):
        self.is_input = value

    @property
    def is_free(self):
        return self.is_free

    @is_free.setter
    def is_free(self, value):
        self.is_free = value

    @property
    def get_def(self):
        return self.def

    @get_def.setter
    def set_def(self, value):
        self.def = value

class PcodeOpAST:
    def __init__(self, pc, uniq, op_type, time):
        self.pc = pc
        self.uniq = uniq
        self.op_type = op_type
        self.time = time

    @property
    def get_pc(self):
        return self.pc

    @get_pc.setter
    def set_pc(self, value):
        self.pc = value

    @property
    def get_uniq(self):
        return self.uniq

    @get_uniq.setter
    def set_uniq(self, value):
        self.uniq = value

    @property
    def op_type(self):
        return self.op_type

    @op_type.setter
    def set_op_type(self, value):
        self.op_type = value

    @property
    def time(self):
        return self.time

    @time.setter
    def set_time(self, value):
        self.time = value