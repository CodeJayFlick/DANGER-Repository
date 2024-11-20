class StringContainer:
    def __init__(self, separator=","):
        self.strings = []
        self.separator = separator

    def add_head(self, *args):
        if args:
            self.strings.insert(0, self.separator.join(map(str, args)))

    def add_tail(self, *args):
        if args:
            self.strings.append(self.separator.join(map(str, args)))

    def get_substring(self, start=0, end=-1):
        return self.separator.join(self.strings[start:end])

    def clone(self):
        new_container = StringContainer()
        for s in self.strings:
            new_container.add_tail(s)
        return new_container

def test_add_head_string_array():
    a = StringContainer(",")
    a.add_tail("a", "b", "c")
    b = StringContainer(",")
    b.add_tail("1", "2", "3")
    c = StringContainer()
    c.add_head("!", "@", "#")
    d = StringContainer()
    d.add_head(1, 2, 3)
    a.add_head(c)
    a.add_tail(b)
    assert a.get_substring() == "123,a,b,c,!@#,a,b,c"

def test_add_tail_string_array():
    a = StringContainer(",")
    a.add_tail("a", "b", "c")
    b = StringContainer(",")
    b.add_tail("1", "2", "3")
    c = StringContainer()
    c.add_head(1, 2, 3)
    d = StringContainer()
    d.add_head("!", "@", "#")
    a.add_tail(c)
    assert a.get_substring() == "a,b,c,!,@,#"

def test_get_sub_string():
    a = StringContainer(",")
    a.add_head("a", "bbb", "cc")
    assert a.get_substring(0) == "a"
    assert a.get_substring(-1) == "cc"
    try:
        a.get_substring(4)
    except IndexError as e:
        pass

def test_get_sub_string_container():
    a = StringContainer(",")
    a.add_tail("a", "bbb", "cc")
    b = a.get_substring(0, 2)
    assert b == "a,bbb"

def test_equal():
    c1 = StringContainer(",")
    c1.add_head("a", "b", "c123")
    c1.add_tail("a", "12", "c")
    c1.add_tail("1284736", "b", "c")
    copy_c = c1.clone()
    assert c1 == copy_c
    assert not (c1 is copy_c)

def test_hash_code():
    c1 = StringContainer(",")
    c1.add_head("a", "b", "c123")
    c1.add_tail("a", "12", "c")
    c1.add_tail("1284736", "b", "c")
    c2 = StringContainer(";")
    c2.add_head("a", "b", "c123")
    c2.add_tail("a", "12", "c")
    c2.add_tail("1284736", "b", "c")
    copy_c = c1.clone()
    assert hash(c1) == hash(copy_c)
    assert not (hash(c1) == hash(c2))
