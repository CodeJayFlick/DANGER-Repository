Here is the translation of the Java code to Python:

```Python
class ForEach:
    def print_list(self, strings):
        for string in strings:
            if string.startswith("XX"):
                print("XX")
            elif string.startswith("YY"):
                continue
            elif string.startswith("ZZ"):
                break
            else:
                print(string)

    def print_list_no_break(self, strings):
        for string in strings:
            if string.startswith("XX"):
                print("XX")
            elif string.startswith("YY"):
                continue
            else:
                print(string)
```

Note that Python does not have a direct equivalent to Java's `System.out.println()`. Instead, the `print()` function is used. Also, Python uses indentation (spaces or tabs) to denote block-level structure, whereas Java uses curly braces `{}` for this purpose.