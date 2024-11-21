Here is the translation of the Java code into Python:

```
class ConstantPoolTagsJava:
    CONSTANT_Class = 7
    CONSTANT_Fieldref = 9
    CONSTANT_Methodref = 10
    CONSTANT_InterfaceMethodref = 11
    CONSTANT_String = 8
    CONSTANT_Integer = 3
    CONSTANT_Float = 4
    CONSTANT_Long = 5
    CONSTANT_Double = 6
    CONSTANT_NameAndType = 12
    CONSTANT_Utf8 = 1
    CONSTANT_MethodHandle = 15
    CONSTANT_MethodType = 16
    CONSTANT_Dynamic = 17
    CONSTANT_InvokeDynamic = 18
    CONSTANT_Module = 19
    CONSTANT_Package = 20

print(ConstantPoolTagsJava.__dict__)
```

Note that in Python, we don't need to use `public` or `final`, as these are not applicable. Also, the class is defined using the `class` keyword instead of `package`. The rest of the code remains similar, with byte values replaced by integer literals.