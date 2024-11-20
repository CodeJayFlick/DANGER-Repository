Here is the translation of the given Java code into Python:

```Python
class CommentWindowContext:
    def __init__(self, provider, comment_table):
        self.provider = provider
        self.comment_table = comment_table

    def get_comment_table(self):
        return self.comment_table


# Example usage:
provider = "Your Provider"
comment_table = {"Column1": ["Value11", "Value12"], "Column2": ["Value21", "Value22"]}

context = CommentWindowContext(provider, comment_table)
print(context.get_comment_table())
```

Please note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of classes extending other classes.