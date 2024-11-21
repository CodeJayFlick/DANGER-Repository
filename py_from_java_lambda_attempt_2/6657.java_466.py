Here is the translation of the Java code to Python:
```
import collections

class MineSequenceTask:
    def __init__(self, miner):
        self.closed_seqs = set()
        self.miner = miner
        super().__init__("Mining Closed Sequences", True, True, True, True)

    def run(self, monitor=None):
        if monitor is None:
            monitor = lambda x: print(x)
        self.closed_seqs = self.miner.mine_closed_sequences(monitor)

    @property
    def closed_seqs(self):
        return self._closed_seqs

class ClosedSequenceMiner:
    pass  # This class needs to be implemented in Python, but the original Java code is not provided.

# Example usage:
miner = ClosedSequenceMiner()  # Implement this class in Python
task = MineSequenceTask(miner)
task.run()
print(task.closed_seqs)  # Should print a set of FrequentSequences
```
Note that I had to make some assumptions about the `ClosedSequenceMiner` class, as it was not provided. In Java, this class is responsible for mining closed sequences from byte sequences, but in Python, you would need to implement its equivalent using a library like scikit-learn or scipy.

Also, I used the `collections.Set` type to represent the set of frequent sequences, since there is no built-in set type in Python.