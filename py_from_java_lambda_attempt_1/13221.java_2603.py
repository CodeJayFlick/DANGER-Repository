Here is the equivalent Python code:

```Python
class MethodHandleBytecodeBehaviors:
    REF_GET_FIELD = 1
    REF_GET_STATIC = 2
    REF_PUT_FIELD = 3
    REF_PUT_STATIC = 4
    REF_INVOKE_VIRTUAL = 5
    REF_INVOCATION_STATIC = 6
    REF_INVOCATION_SPECIAL = 7
    REF_NEW_INVOCATION_SPECIAL = 8
    REF_INVOCATION_INTERFACE = 9

    @staticmethod
    def get_name(kind):
        for field in MethodHandleBytecodeBehaviors.__dict__:
            if isinstance(field, int) and str.startswith("REF_", field):
                if method_handle_bytecode_behaviors[field] == kind:
                    return field
        return f"Unrecognized kind: 0x{kind:x}"
```

Note that Python does not have a direct equivalent to Java's `public final static` keywords. The class is defined as just `class MethodHandleBytecodeBehaviors:` and the methods are defined without any access modifiers (i.e., they default to being instance methods).