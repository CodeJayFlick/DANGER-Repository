Here is the equivalent Python code:

```
class VerifyError:
    BAD_CLASS_HARD = 0x01
    BAD_CLASS_SOFT = 0x02
    NO_CLASS = 0x04
    NO_FIELD = 0x08
    NO_METHOD = 0x10
    ACCESS_CLASS = 0x20
    ACCESS_FIELD = 0x40
    ACCESS_METHOD = 0x80
    CLASS_CHANGE = 0x100
    INSTANTIATION = 0x200
    FORCE_INTERPRETER = 0x400
    LOCKING = 0x800
    SKIP_COMPILER = 0x80000000

VerifyError.__dict__.update({
    'BAD_CLASS_HARD': VerifyError.BAD_CLASS_HARD,
    'BAD_CLASS_SOFT': VerifyError.BAD_CLASS_SOFT,
    'NO_CLASS': VerifyError.NO_CLASS,
    'NO_FIELD': VerifyError.NO_FIELD,
    'NO_METHOD': VerifyError.NO_METHOD,
    'ACCESS_CLASS': VerifyError.ACCESS_CLASS,
    'ACCESS_FIELD': VerifyError.ACCESS_FIELD,
    'ACCESS_METHOD': VerifyError.ACCESS_METHOD,
    'CLASS_CHANGE': VerifyError.CLASS_CHANGE,
    'INSTANTIATION': VerifyError.INSTANTIATION,
    'FORCE_INTERPRETER': VerifyError.FORCE_INTERPRETER,
    'LOCKING': VerifyError.LOCKING,
    'SKIP_COMPILER': VerifyError.SKIP_COMPILER
})
```

Note that Python does not have a direct equivalent to Java's `public final static` declaration, so I've simply defined the constants as class attributes. The `__dict__.update()` method is used to create a dictionary of constant names and values within the class.