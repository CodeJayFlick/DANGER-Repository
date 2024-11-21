Here is the translation of the given Java code into Python:

```Python
class SingleEntSubIterator:
    def __init__(self, model, monitor=None):
        self.model = model
        if monitor is None:
            self.monitor = TaskMonitor.DUMMY
        else:
            self.monitor = monitor
        self.addr_set = None
        self.next_sub = None
        self.sub_list = []
        self.model_m_iter = None

    def __init_with_addr_set(self, model, addr_set, monitor):
        self.__init__(model, monitor)
        self.addr_set = addr_set

    def hasNext(self) -> bool:
        if self.next_sub is not None:
            return True
        if len(self.sub_list) > 0:
            self.next_sub = self.sub_list.pop(0)
            return True
        while self.model_m_iter.hasNext():
            model_m_sub = self.model_m_iter.next()
            entry_points = model_m_sub.get_start_addresses()
            for i in range(len(entry_points)):
                sub = self.model.get_code_block_at(entry_points[i], self.monitor)
                if sub is None:
                    continue  # should only happen with screwy code
                if self.monitor.is_cancelled():
                    return False
                if self.addr_set is not None and not sub.intersects(self.addr_set):
                    continue
                self.sub_list.append(sub)
            if len(self.sub_list) > 0:
                self.next_sub = self.sub_list.pop(0)
                return True
        return False

    def next(self) -> 'CodeBlock':
        if self.next_sub is None:
            self.hasNext()
        ret_sub = self.next_sub
        self.next_sub = None
        return ret_sub


class CodeBlockIterator:
    pass  # This class doesn't have any methods or attributes that need to be translated.
```

Please note that Python does not support operator overloading like Java, so the `@Override` annotation is not needed in Python. Also, some types and classes (like LinkedList) are replaced with their equivalent Python counterparts.