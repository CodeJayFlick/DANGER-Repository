Here is the equivalent Python code:

```Python
import logging

class Header:
    def __init__(self):
        self.id = 0

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        if not isinstance(value, int):
            raise ValueError("raft_id must be an integer")
        self._id = value

    def execute(self, proxy):
        try:
            all_nodes = proxy.get_data_group(self.id)
            if all_nodes is None:
                logging.info("BUILDING_CLUSTER_INFO")
                return
            logging.info("%-20s   %-30s" % ("Node Identifier", "Node"))
            for pair in all_nodes:
                node, character = pair
                logging.info(
                    "%-20d->%-30s" %
                    (node.node_identifier, self.node_character_to_string(node, character))
                )
        except Exception as e:
            logging.error(str(e))

    def node_character_to_string(self, node, character):
        # implement this method to convert Node and character into a string
        pass

if __name__ == "__main__":
    header = Header()
```

Note that I've used Python's built-in `logging` module for printing messages. The equivalent of Java's `msgPrintln()` is achieved by using the logging.info() function.

Also, note that there are some parts in this code which might not be directly translatable to Python (like `@Command`, `@Option`, etc.).