Here is the equivalent Python code:

```Python
class ContextRegisterInfo:
    def __init__(self, name):
        self.name = name
        self.value = None

def test_equals():
    one = 1
    three = 3

    cReg1 = "contextRegister1"
    cReg2 = "contextRegister2"

    info1 = ContextRegisterInfo(cReg1)
    info2 = ContextRegisterInfo(cReg1)
    info3 = ContextRegisterInfo(cReg2)

    # test comparison with None
    assert not (info1 is None)

    # test comparison with object of wrong class
    assert not isinstance(info1, str)

    # test registers with no values set
    assert info1 == info1
    assert info1 == info2
    assert info2 == info1
    assert info1 != info3
    assert info3 != info1

    info1.value = one
    info2.value = one
    info3.value = three

    assert info1 == info1
    assert info1 == info2
    assert info2 == info1
    assert info1 != info3
    assert info3 != info1

if __name__ == "__main__":
    test_equals()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, you would typically define the function as is and then call it in your main code block if needed (like I did with `test_equals()`).