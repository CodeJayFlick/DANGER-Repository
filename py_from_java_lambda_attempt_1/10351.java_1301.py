Here is the translation of the Java code to Python:
```
class ClassExclusionFilter:
    def __init__(self, *exclusions):
        self.exclusion_set = set(exclusions)

    def accepts(self, c):
        return c not in self.exclusion_set
```
Note that I've used the `set` type from the built-in `collections` module to implement the exclusion set. The rest of the code is straightforward translation from Java to Python.

Here's a brief explanation:

* In Java, we had a `Set<Class<?>>` called `exclusionSet`. In Python, we use a `set` object with no type hinting.
* The constructor (`__init__`) takes variable-length arguments (`*exclusions`) and initializes the exclusion set using the `set()` function from the `collections` module. We pass in each of the exclusions as separate elements to create the set.
* The `accepts` method is similar to its Java counterpart: it returns a boolean indicating whether the given class `c` is not present in the exclusion set.

That's it!