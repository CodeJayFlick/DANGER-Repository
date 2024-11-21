class RedBlackLongKeySet:
    def __init__(self):
        self.root = None
        self.size = 0

    NODESIZE = 15
    RED = 0
    BLACK = 1

    class RBNode:
        def __init__(self, key, parent=None):
            self.key = key
            self.color = BLACK
            self.parent = parent
            self.left = None
            self.right = None

    def size(self):
        return self.size

    def contains_key(self, key):
        node = self.root
        while node is not None:
            if key == node.key:
                return True
            elif key < node.key:
                node = node.left
            else:
                node = node.right
        return False

    def getFirst(self):
        if self.root is None:
            return -1
        node = self.root
        while node.left is not None:
            node = node.left
        return node.key

    def getLast(self):
        if self.root is None:
            return -1
        node = self.root
        while node.right is not None:
            node = node.right
        return node.key

    def getNext(self, key):
        if key < 0:
            raise IndexOutOfBoundsException()
        foundValue = False
        bestkey = 0
        node = self.root
        while node is not None:
            if key >= node.key:
                node = node.right
            else:
                foundValue = True
                bestkey = node.key
                node = node.left
        if foundValue:
            return bestkey
        return -1

    def getPrevious(self, key):
        if key < 0:
            raise IndexOutOfBoundsException()
        foundValue = False
        bestkey = 0
        node = self.root
        while node is not None:
            if key <= node.key:
                node = node.right
            else:
                foundValue = True
                bestkey = node.key
                node = node.left
        if foundValue:
            return bestkey
        return -1

    def put(self, key):
        if key < 0:
            raise IndexOutOfBoundsException()
        if self.root is None:
            self.size += 1
            self.root = RBNode(key)
        else:
            node = self.root
            while True:
                if key == node.key:
                    return
                elif key < node.key:
                    if node.left is not None:
                        node = node.left
                    else:
                        self.size += 1
                        node.left = RBNode(key, node)
                        fixAfterInsertion(node.left)
                        return
                else:
                    if node.right is not None:
                        node = node.right
                    else:
                        self.size += 1
                        node.right = RBNode(key, node)
                        fixAfterInsertion(node.right)
                        return

    def remove(self, key):
        if key < 0:
            raise IndexOutOfBoundsException()
        node = self.root
        while node is not None:
            if key == node.key:
                break
            elif key < node.key:
                node = node.left
            else:
                node = node.right
        if node is None:
            return False
        self.size -= 1
        deleteEntry(node)
        return True

    def removeAll(self):
        self.size = 0
        self.root = None

    def isEmpty(self):
        return self.size == 0


def colorOf(p):
    return BLACK if p is None else p.color


def parentOf(p):
    return None if p is None else p.parent


def setColor(p, c):
    if p is not None:
        p.color = c


def leftOf(p):
    return None if p is None else p.left


def rightOf(p):
    return None if p is None else p.right


def rotateLeft(p):
    r = p.right
    p.right = r.left
    if r.left is not None:
        r.left.parent = p
    r.parent = p.parent
    if p.parent is None:
        RedBlackLongKeySet.root = r
    elif p == p.parent.left:
        p.parent.left = r
    else:
        p.parent.right = r
    r.left = p


def rotateRight(p):
    l = p.left
    p.left = l.right
    if l.right is not None:
        l.right.parent = p
    l.parent = p.parent
    if p.parent is None:
        RedBlackLongKeySet.root = l
    elif p == p.parent.right:
        p.parent.right = l
    else:
        p.parent.left = l
    l.right = p


def fixAfterInsertion(x):
    x.color = RED

    while x is not RedBlackLongKeySet.root and colorOf(x) == BLACK:
        if leftOf(parentOf(x)) is not None and colorOf(leftOf(parentOf(x))) == RED:
            setColor(parentOf(x), RED)
            setColor(rightOf(parentOf(x)), BLACK)
            rotateLeft(parentOf(parentOf(x)))
            x = parentOf(parentOf(x))
        else:
            if rightOf(parentOf(x)) is not None and colorOf(rightOf(parentOf(x))) == RED:
                setColor(parentOf(x), RED)
                setColor(leftOf(parentOf(x)), BLACK)
                rotateRight(parentOf(parentOf(x)))
                x = parentOf(parentOf(x))
            else:
                break
    if RedBlackLongKeySet.root is not None and colorOf(RedBlackLongKeySet.root) == RED:
        fixAfterInsertion(RedBlackLongKeySet.root)


def deleteEntry(p):
    if p.left is not None and p.right is not None:
        s = rightOf(p)
        if colorOf(s) == RED:
            setColor(s, BLACK)
            setColor(parentOf(p), RED)
            rotateLeft(p)
            s = rightOf(p)
        if leftOf(s) is not None and colorOf(leftOf(s)) == BLACK and colorOf(rightOf(s)) == BLACK:
            setColor(s, RED)
            p.color = BLACK
            fixAfterDeletion(p)
            return
    swapPosition(p, parentOf(parentOf(p)))
    if yWasLeftChild:
        py.left = x
        py.right = rx
    else:
        py.right = x
        py.left = ly

    # Swap colors
    c = x.color
    x.color = y.color
    y.color = c


def swapPosition(x, y):
    px = parentOf(x)
    lx = leftOf(x)
    rx = rightOf(x)

    if x is y:
        return

    if x is py:
        py.left = y
        py.right = ry
    else:
        py.right = y
        py.left = ly

    # Swap colors
    c = x.color
    x.color = y.color
    y.color = c


def writeObject(s):
    s.defaultWriteObject()
    s.writeInt(self.size)
    key = self.getFirst()
    while key >= 0:
        s.writeLong(key)
        key = self.getNext(key)


def readObject(s, sz):
    s.defaultReadObject()
    self.size = s.readInt()
    root = buildFromSorted(0, 0, sz - 1, computeRedLevel(sz), s)

def buildFromSorted(level, lo, hi, redLevel, str):
    if hi < lo:
        return None

    mid = (lo + hi) // 2

    left = None
    if lo < mid:
        left = buildFromSorted(level+1, lo, mid - 1, redLevel, s)
    key = s.readLong()

    middle = RBNode(key)

    # color nodes in non-full bottommost level red
    if level == redLevel:
        middle.color = RED

    if left is not None:
        middle.left = left
        left.parent = middle
    if mid < hi:
        right = buildFromSorted(level+1, mid + 1, hi, redLevel, s)
        middle.right = right
        right.parent = middle
    return middle


def computeRedLevel(sz):
    level = 0
    for m in range(sz - 1, 0, -2):
        level += 1
    return level

