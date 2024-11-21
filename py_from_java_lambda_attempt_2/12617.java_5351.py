Here is the translation of the given Java code into Python:

```Python
class BlockMap:
    def __init__(self):
        self.factory = None
        self.sortlist = []
        self.leaflist = []
        self.gotoreflist = []

    class GotoReference:
        def __init__(self, gotoblock, rootindex, depth):
            self.gotoblock = gotoblock
            self.rootindex = rootindex
            self.depth = depth

    def __init__(self, fac=None):
        if fac is not None:
            self.factory = fac
            self.leaflist = []
            self.gotoreflist = []
            self.sortlist = []

    def getAddressFactory(self):
        return self.factory

    @staticmethod
    def sortList(list_):
        list_.sort(key=lambda x: x.index)

    @staticmethod
    def resolveBlock(btype):
        if btype == 0:
            return PcodeBlockBasic()
        elif btype == 1:
            return BlockCondition()
        # Add more cases as needed

    def findLevelBlock(self, ind):
        return self.findBlock(self.sortlist, ind)

    def sortLevelList(self):
        self.sortList(self.sortlist)

    @staticmethod
    def findBlock(list_, ind):
        min_ = 0
        max_ = len(list_) - 1

        while min_ <= max_:
            mid = (min_ + max_) // 2
            block = list_[mid]
            if block.index == ind:
                return block
            elif block.index < ind:
                min_ = mid + 1
            else:
                max_ = mid - 1

        return None

    def createBlock(self, name, index):
        btype = PcodeBlock.nameToType(name)
        res = self.resolveBlock(btype)
        res.setIndex(index)
        self.sortlist.append(res)

        if (btype == 0 or btype == 1 or btype == 2):  # Add more cases as needed
            self.leaflist.append(res)

        return res

    def addGotoRef(self, gblock, rootindex, depth):
        ref = BlockMap.GotoReference(gblock, rootindex, depth)
        self.gotoreflist.append(ref)

    def resolveGotoReferences(self):
        self.sortList(self.leaflist)
        for i in range(len(self.gotoreflist)):
            gotoref = self.gotoreflist[i]
            bl = self.findBlock(self.leaflist, gotoref.rootindex)
            depth = gotoref.depth

            while depth > 0:
                depth -= 1
                bl = bl.getParent()

            if isinstance(gotoref.gotoblock, BlockGoto):
                gotoblock = gotoref.gotoblock
                gotoblock.setGotoTarget(bl)
            elif isinstance(goteref.gotoblock, BlockIfGoto):
                gotoblock = gotoref.gotoblock
                gotoblock.setGotoTarget(bl)
            elif isinstance(goteref.gotoblock, BlockMultiGoto):
                gotoblock = gotoref.gotoblock
                gotoblock.addBlock(bl)

class PcodeBlock:
    def __init__(self):
        pass

# Add more classes and methods as needed