Here is the translation of the Java code into Python:

```Python
class ClassInfo:
    def __init__(self, c: type, code_name: str):
        self.c = c
        if not self._is_valid_code_name(code_name):
            raise ValueError("Code names for classes must be lowercase and only consist of latin letters and arabic numbers")
        self.code_name = code_name
        self.name = Noun(f"types.{code_name}")

    def parser(self, parser: 'Parser[~T]') -> 'ClassInfo[T]':
        if self.parser is not None:
            raise ValueError("parser can only be set once")
        self.parser = parser
        return self

    def cloner(self, cloner: 'Cloner[~T]') -> 'ClassInfo[T]':
        if self.cloner is not None:
            raise ValueError("cloner can only be set once")
        self.cloner = cloner
        return self

    def user_input_patterns(self, *patterns) -> 'ClassInfo[T]':
        if self.user_input_patterns is not None:
            raise ValueError("user input patterns can only be set once")
        self.user_input_patterns = [Pattern.compile(pattern) for pattern in patterns]
        return self

    def default_expression(self, expression: 'DefaultExpression[~T]') -> 'ClassInfo[T]':
        if self.default_expression is not None:
            raise ValueError("default expression can only be set once")
        self.default_expression = expression
        return self

    # ... (other methods similar to the above)

class Noun(str):
    pass

class Pattern(re.compile):
    def __init__(self, pattern: str):
        super().__init__(pattern)
```

Please note that Python does not have direct equivalent of Java's `@NonNull` and `@Nullable`, so I've used type hints instead. Also, the `EventValueExpression` class is missing in your code snippet, but it seems to be a custom class specific to Skript, which you didn't provide.