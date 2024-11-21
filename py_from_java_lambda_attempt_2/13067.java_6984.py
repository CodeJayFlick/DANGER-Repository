Here is the translation of the given Java code into Python:

```Python
class XmlPullParser:
    def __init__(self):
        pass

    def end(self):
        if not self.has_next():
            raise XmlException("at EOF but expected end element")
        next = self.next()
        if not next.is_end():
            raise XmlException(f"got {('start' if next.is_start() else 'content')} element but expected end element")
        return next

    def end(self, element):
        name = element.name
        if not self.has_next():
            raise XmlException(f"at EOF but expected end element {name}")
        next = self.next()
        if not name == next.name:
            raise XmlException(f"got element {next.name} but expected end element {name}")
        if not next.is_end():
            raise XmlException(f"got {'start' if next.is_start() else 'content'} element but expected end element {name}")
        return next

    def get_column_number(self):
        if self.has_next():
            return self.peek().column_number
        return -1

    def get_current_level(self):
        if self.has_next():
            return self.peek().level
        return -1

    def get_line_number(self):
        if self.has_next():
            return self.peek().line_number
        return -1

    @staticmethod
    def collapse(*s):
        sb = StringBuilder()
        if s is None:
            sb.append("(null)")
        else:
            sep = ""
            sb.append("[ ")
            for t in s:
                sb.append(sep)
                sb.append(t)
                sep = ", "
            sb.append(" ]")
        return str(sb)

    def start(self, *names):
        if not self.has_next():
            raise XmlException(f"at EOF but expected start element {self.collapse(*names)}")
        next = self.next()
        if not next.is_start():
            raise XmlException(f"got {'end' if next.is_end() else 'content'} element but expected start element {self.collapse(*names)}")
        found = len(names) == 0
        for name in names:
            if name == next.name:
                found = True
                break
        if not found:
            raise XmlException(f"got element {next.name} but expected start element {self.collapse(*names)}")
        return next

    def soft_start(self, *names):
        if not self.has_next():
            raise XmlException(f"at EOF but expected soft start element {self.collapse(*names)}")
        peek = self.peek()
        if not peek.is_start():
            return None
        found = len(names) == 0
        for name in names:
            if name == peek.name:
                found = True
                break
        if not found:
            return None
        return self.next()

    def discard_subtree(self):
        return self.discard_subtree(self.peek())

    def discard_subtree(self, element):
        if element is self.peek():
            # we're being asked to skip the entire subtree starting from the front of the queue
            if element.is_start():
                name = element.name
                level = element.level
                next = self.next()
                count = 1
                while not (next.is_end() and next.level == level and next.name == name):
                    next = self.next()
                    count += 1
                return count
            # the front of the queue is a content element or an end element...so only discard it
            self.next()
            return 1
        # we were provided with an arbitrary prior element which will be used as the "start" element...now we try to skip until past the matching end element
        name = element.name
        level = element.level
        peek = self.peek()
        if peek.level < level:
            # the "start" element was a child of a prior sibling of the front of the queue
            # so that ship has sailed (no skipping, just return)
            return 0
        elif peek.level == level:
            # the "start" element is the same level as the front of the queue
            if element.is_start() and peek.is_end() and element.name == peek.name:
                # hey, the "start" *is* the actual start, and the front of the queue
                # is the actual end (presumably).  So pop it and return...
                self.next()
                return 1
            # looks like the front of the queue is a sibling. Don't skip anything,
            # just return
            return 0
        else:
            # the "start" is an ancestor of the front of the queue. Pop stuff off until we get past the end element.
            next = self.next()
            count = 1
            while not (next.is_end() and next.level == level and next.name == name):
                next = self.next()
                count += 1
            return count

    def discard_subtree(self, element_name):
        start = self.start(element_name)
        return self.discard_subtree(start) + 1


class XmlException(Exception):
    pass


class XmlElement:
    def __init__(self, name, level, is_start=False, is_end=False):
        self.name = name
        self.level = level
        self.is_start = is_start
        self.is_end = is_end

    @property
    def column_number(self):
        return 0

    @property
    def line_number(self):
        return 0


class XmlPullParserImpl(XmlPullParser):
    def __init__(self, queue):
        self.queue = queue
        self.peeked = None

    def has_next(self):
        return len(self.queue) > 0 and not (self.peek().is_end() or self.peek().level == -1)

    def next(self):
        if self.has_next():
            element = self.queue.pop(0)
            self.peeked = element
            return element
        else:
            raise XmlException("at EOF")

    def peek(self):
        if not hasattr(self, 'peeked'):
            if len(self.queue) > 0:
                self.peeked = self.queue[0]
            else:
                self.peeked = None
        return self.peeked


# Example usage:

queue = [XmlElement('start', 1), XmlElement('child', 2), XmlElement('grandchild', 3, is_end=True),
         XmlElement('end', -1)]

parser = XmlPullParserImpl(queue)

print(parser.start())  # prints the first element in the queue
print(parser.end())     # raises an exception because there's no end tag to match

try:
    print(parser.discard_subtree())
except XmlException as e:
    print(e)  # prints "at EOF but expected start element"

try:
    parser.start('start')
except XmlException as e:
    print(e)  # prints "got {'end' if next.is_end() else 'content'} element but expected start element"
```