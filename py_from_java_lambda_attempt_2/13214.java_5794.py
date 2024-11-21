Here is the translation of the Java code to Python:

```Python
class LdcMethods:
    VALUE = "value"

    def __init__(self):
        raise AssertionError()

    @staticmethod
    def get_pcode_for_ldc(p_code, constant_pool_index, constant_pool):
        tag = constant_pool[constant_pool_index].tag
        if tag in [ConstantPoolTagsJava.CONSTANT_Class,
                   ConstantPoolTagsJava.CONSTANT_Float,
                   ConstantPoolTagsJava.CONSTANT_Integer,
                   ConstantPoolTagsJava.CONSTANT_MethodHandle,
                   ConstantPoolTagsJava.CONSTANT_MethodType,
                   ConstantPoolTagsJava.CONSTANT_String]:
            p_code.emit_assign_varnode_from_pcode_op_call(VALUE, 4, "0", str(constant_pool_index), "ldc")
            p_code.emit_push_cat1_value(VALUE)
        elif tag in [ConstantPoolTagsJava.CONSTANT_Double, ConstantPoolTagsJava.CONSTANT_Long]:
            p_code.emit_assign_varnode_from_pcode_op_call(VALUE, 8, "0", str(constant_pool_index), "ldc2_w")
            p_code.emit_push_cat2_value(VALUE)
        else:
            raise ValueError(f"Invalid load from constant pool: tag {tag}")

class ConstantPoolTagsJava:
    CONSTANT_Class = ...
    CONSTANT_Float = ...
    CONSTANT_Integer = ...
    CONSTANT_MethodHandle = ...
    CONSTANT_MethodType = ...
    CONSTANT_String = ...

    CONSTANT_Double = ...
    CONSTANT_Long = ...
```

Note that I've replaced the Java-specific classes and methods with their Python equivalents. For example, `public static` is not necessary in Python because everything is public by default. The `switch` statement has been replaced with a series of `if-elif-else` statements to handle different cases.