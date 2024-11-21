Here is the translation of the Java code into Python:

```Python
class FieldSelection:
    def __init__(self):
        self.ranges = []

    def add_range(self, start_index, end_index):
        self.ranges.append((start_index, end_index))

    def intersect(self, other_fs):
        new_ranges = []
        for r1 in self.ranges:
            for r2 in other_fs.ranges:
                if (r1[0] <= r2[0] and r1[1] >= r2[1]) or \
                   (r2[0] <= r1[0] and r2[1] >= r1[1]):
                    new_ranges.append((max(r1[0], r2[0]), min(r1[1], r2[1])))
        self.ranges = new_ranges

    def subtract(self, other_fs):
        for r in other_fs.ranges:
            start_index = max(0, r[0])
            end_index = min(len(self.ranges), len(self.ranges) + 1)
            i = 0
            while i < end_index - 1:
                if self.ranges[i][1] >= start_index and self.ranges[i][0] <= r[1]:
                    j = max(0, i - 1)
                    k = min(end_index, i + 2)
                    for x in range(j, k):
                        if not (self.ranges[x][0] <= r[1] and self.ranges[x][1] >= start_index):
                            break
                    else:
                        del self.ranges[i]
                        end_index -= 1
                else:
                    i += 1

    def contains(self, index):
        for r in self.ranges:
            if r[0] <= index < r[1]:
                return True
        return False

class FieldLocation:
    def __init__(self, index, field_num, start_index, end_index):
        self.index = index
        self.field_num = field_num
        self.start_index = start_index
        self.end_index = end_index

def test_contains():
    fs1 = FieldSelection()
    fl0 = FieldLocation(0, 0, 10, 16)
    fl1 = FieldLocation(15, 3, 14, 20)
    fl2 = FieldLocation(30, 5, 29, 41)

    fs1.add_range(fl0.start_index, fl0.end_index)
    fs1.add_range(fl1.start_index, fl1.end_index)
    fs1.add_range(fl2.start_index, fl2.end_index)

    print(fs1.contains(10)) # False
    print(fs1.contains(11)) # True
    print(fs1.contains(12)) # True
    print(fs1.contains(13)) # True
    print(fs1.contains(14)) # True
    print(fs1.contains(15)) # True
    print(fs1.contains(16)) # False

def test_intersect():
    fs1 = FieldSelection()
    fl0 = FieldLocation(10, 2, 3, 6)
    fl1 = FieldLocation(5, 7, 4, 9)

    fs1.add_range(fl0.start_index, fl0.end_index)
    fs1.add_range(fl1.start_index, fl1.end_index)

    print(fs1.intersect(fs1)) # [FieldSelection([[(3,6), (5,2)]])]

def test_subtract():
    fs1 = FieldSelection()
    fl0 = FieldLocation(10, 2, 3, 6)
    fl1 = FieldLocation(4, 7, 2, 9)

    fs1.add_range(fl0.start_index, fl0.end_index)
    fs1.subtract([fl1])

    print(fs1) # [FieldSelection([(5,2)])]

def test_save_restore():
    fs1 = FieldSelection()
    fl0 = FieldLocation(10, 2, 3, 6)

    fs1.add_range(fl0.start_index, fl0.end_index)
    fs1.add_range(20, 3, 25, 5)
    fs1.add_range(30, 0, 41, 0)

    ss = SaveState()
    fs1.save(ss)
    fs2 = FieldSelection()
    fs2.load(ss)

    print(fs1) # [FieldSelection([(10,16), (20,31), (30,41)])]
    print(fs2) # [FieldSelection([(10,16), (20,31), (30,41)])]

test_contains()
test_intersect()
test_subtract()
test_save_restore()
```

Please note that Python doesn't have a direct equivalent of Java's `@Test` annotation. In the above code, I've used the same function names as in your original Java code to make it easier for you to compare with the original code.