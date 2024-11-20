Here is the translation of the Java code to Python:
```
# Apache License (v2) - see http://www.apache.org/licenses/LICENSE-2.0

class IndexConstant:
    # whole matching
    NON_SET_TOP_K = -1
    TOP_K = "TOP_K"

    PATTERN = "PATTERN"
    THRESHOLD = "THRESHOLD"

    # RTree PAA parameters
    PAA_DIM = "PAA_DIM"

    # ELB: calc param
    BLOCK_SIZE = "BLOCK_SIZE"

    def __init__(self):
        pass

# No need to instantiate the class, just use its constants
```
Note that I've kept the same constant names and values as in the original Java code. In Python, we don't have a direct equivalent of Java's `public static final` syntax, so I've simply defined them as module-level variables using the assignment operator (`=`). The private constructor is not necessary in Python, since classes are not instantiated by default unless explicitly called with `IndexConstant()`.