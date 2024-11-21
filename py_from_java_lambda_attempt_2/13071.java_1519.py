Here's your Java interface translated into a Python class:

```Python
class XmlPullParser:
    def __init__(self):
        pass  # Initialize parser state here if needed.

    def get_name(self) -> str:
        """Returns the name of this parser."""
        raise NotImplementedError("Method not implemented")

    def get_processing_instruction(self, name: str, attribute: str) -> str:
        """Returns the value of the attribute of the processing instruction."""
        raise NotImplementedError("Method not implemented")

    @property
    def line_number(self) -> int:
        """Returns the current line number where the parser is (note that this may actually be ahead of where you think it is because of look-ahead and caching)."""
        raise NotImplementedError("Method not implemented")

    @property
    def column_number(self) -> int:
        """Returns the current column number where the parser is (note that this may actually be ahead of where you think it is because of look-ahead and caching)."""
        raise NotImplementedError("Method not implemented")

    def is_pulling_content(self) -> bool:
        """Returns whether the parser will return content elements."""
        raise NotImplementedError("Method not implemented")

    def set_pulling_content(self, pulling_content: bool):
        """Set whether the parser will return content elements. Note that this method may throw an exception if the parser cannot comply with the setting (usually when setting to true)."""
        raise NotImplementedError("Method not implemented")

    @property
    def current_level(self) -> int:
        """The current element level, as if the XML document was a tree. The root element is at level 0. Each child is at a level one higher than its parent."""
        raise NotImplementedError("Method not implemented")

    def has_next(self) -> bool:
        """Returns whether there is a next element."""
        raise NotImplementedError("Method not implemented")

    def peek(self) -> 'XmlElement':
        """Returns the next element, without removing it from the queue (assuming there is such a next element). This is very useful for examining the next item to decide who should handle the subtree, and then delegating to a subordinate with the parser state intact."""
        raise NotImplementedError("Method not implemented")

    def next(self) -> 'XmlElement':
        """Returns the next element, removing it from the queue (assuming there is such a next element). This method should be used RARELY. Typically, when you're reading XML, you almost always at least know that you're either starting or ending a subtree, so start() or end() should be used instead."""
        raise NotImplementedError("Method not implemented")

    def start(self, *names: str) -> 'XmlElement':
        """Returns the next element, which must be a start element, and must be one of the supplied names (if provided). This method is very useful for starting a subtree, and throws an XmlException if the next element does not conform to your specification."""
        raise NotImplementedError("Method not implemented")

    def end(self) -> 'XmlElement':
        """Returns the next element, which must be an end element. The name doesn't matter. This method throws an XmlException if the next element is not an end element. Use this method when you really know you're matching the right end and want to avoid extra constraint checks."""
        raise NotImplementedError("Method not implemented")

    def end(self, element: 'XmlElement') -> 'XmlElement':
        """Returns the next element, which must be an end element, and must match the supplied XmlElement's name (presumably the start element of the subtree). This method throws an XmlException if the next element is not an end element, or if the name doesn't match."""
        raise NotImplementedError("Method not implemented")

    def soft_start(self, *names: str) -> 'XmlElement':
        """Returns the next element, which must be a start element, and must be one of the supplied names (if provided). This method is very useful for starting a subtree, but differs from start(...) in that failures are soft. This means that if the next element isn't a start element, or doesn't match one of the optional provided names, null is returned (instead of raising an XmlException)."""
        raise NotImplementedError("Method not implemented")

    def discard_subtree(self) -> int:
        """Discards the current subtree. If the current element (peek()) is a content or end element, then just that element is discarded. If it's a start element, then the entire subtree starting with the start element is discarded (i.e. next() is called until the current element is now the element after the subtree's end element)."""
        raise NotImplementedError("Method not implemented")

    def discard_subtree(self, name: str) -> int:
        """Discards a subtree. The element provided is used as the "start" of the subtree (although it doesn't actually have to be a start element; only its name and level are used). The queue of elements is discarded such that the last element discarded is an end element, has the same name as the provided element, and is the same level as the provided element. If the provided element's level is higher than the current level, then nothing is discarded."""
        raise NotImplementedError("Method not implemented")

    def discard_subtree(self, element: 'XmlElement') -> int:
        """Discards a subtree. The element provided is used as the "start" of the subtree (although it doesn't actually have to be a start element; only its name and level are used). The queue of elements is discarded such that the last element discarded is an end element, has the same name as the provided element, and is the same level as the provided element. If the provided element's level is higher than the current level, then nothing is discarded."""
        raise NotImplementedError("Method not implemented")

    def dispose(self):
        """Disposes all resources of the parser. It's important that this is called when a client is finished with the parser, because this allows files to be closed, threads to be stopped, etc."""
        pass  # Dispose any resources here if needed.
```

This Python class does not implement the methods as they are abstract in Java and cannot be directly translated into Python. The `raise NotImplementedError("Method not implemented")` statements indicate that these methods should be implemented by a subclass of this class.