Here is the translation of the given Java code into equivalent Python code:

```Python
import unittest
from collections import ArrayList, SequenceItem

class ClosedSequenceMinerTest(unittest.TestCase):

    def test1(self):
        sequences = ArrayList()
        sequences.append(Sequence("B", 2))
        database = SequenceDatabase(sequences, 1)
        miner = ClosedSequenceMiner(database, 2)
        closedSeqs = miner.mineClosedSequences(None)
        self.assertEqual(1, len(closedSeqs))

        closedSeq1 = ArrayList()
        closedSeq1.append(SequenceItem("B", 0))
        seqAndCount1 = FrequentSequence(closedSeq1, 2)
        self.assertTrue(seqAndCount1 in closedSeqs)

    def test2(self):
        sequences = ArrayList()
        sequences.append(Sequence("A", 1))
        sequences.append(Sequence("B", 2))
        database = SequenceDatabase(sequences, 1)
        miner = ClosedSequenceMiner(database, 2)
        closedSeqs = miner.mineClosedSequences(None)
        self.assertEqual(1, len(closedSeqs))

        closedSeq1 = ArrayList()
        closedSeq1.append(SequenceItem("B", 0))
        seqAndCount1 = FrequentSequence(closedSeq1, 2)
        self.assertTrue(seqAndCount1 in closedSeqs)

    def test3(self):
        sequences = ArrayList()
        sequences.append(Sequence("A", 1))
        sequences.append(Sequence("B", 2))
        sequences.append(Sequence("C", 1))
        database = SequenceDatabase(sequences, 1)
        miner = ClosedSequenceMiner(database, 2)
        closedSeqs = miner.mineClosedSequences(None)
        self.assertEqual(1, len(closedSeqs))

        closedSeq1 = ArrayList()
        closedSeq1.append(SequenceItem("B", 0))
        seqAndCount1 = FrequentSequence(closedSeq1, 2)
        self.assertTrue(seqAndCount1 in closedSeqs)

    def test4(self):
        sequences = ArrayList()
        sequences.append(Sequence("A", 1))
        sequences.append(Sequence("B", 2))
        sequences.append(Sequence("C", 2))
        database = SequenceDatabase(sequences, 1)
        miner = ClosedSequenceMiner(database, 2)
        closedSeqs = miner.mineClosedSequences(None)
        self.assertEqual(2, len(closedSeqs))

        closedSeq1 = ArrayList()
        closedSeq1.append(SequenceItem("B", 0))
        seqAndCount1 = FrequentSequence(closedSeq1, 2)
        self.assertTrue(seqAndCount1 in closedSeqs)

        closedSeq2 = ArrayList()
        closedSeq2.append(SequenceItem("C", 0))
        seqAndCount2 = FrequentSequence(closedSeq2, 2)
        self.assertTrue(seqAndCount2 in closedSeqs)

    def test5(self):
        sequences = ArrayList()
        sequences.append(Sequence("ABCD", 2))
        database = SequenceDatabase(sequences, 4)
        miner = ClosedSequenceMiner(database, 2)
        closedSeqs = miner.mineClosedSequences(None)
        self.assertEqual(1, len(closedSeqs))

        closedSeq1 = ArrayList()
        closedSeq1.append(SequenceItem("A", 0))
        closedSeq1.append(SequenceItem("B", 1))
        closedSeq1.append(SequenceItem("C", 2))
        closedSeq1.append(SequenceItem("D", 3))
        seqAndCount1 = FrequentSequence(closedSeq1, 2)
        self.assertTrue(seqAndCount1 in closedSeqs)

    def test6(self):
        sequences = ArrayList()
        sequences.append(Sequence("ABCD", 2))
        sequences.append(Sequence("XBYD", 2))
        sequences.append(Sequence("AUCV", 2))
        sequences.append(Sequence("AAAA", 2))
        database = SequenceDatabase(sequences, 4)
        miner = ClosedSequenceMiner(database, 3)
        closedSeqs = miner.mineClosedSequences(None)
        self.assertEqual(3, len(closedSeqs))

        closedSeq1 = ArrayList()
        closedSeq1.append(SequenceItem("B", 1))
        seqAndCount1 = FrequentSequence(closedSeq1, 4)
        self.assertTrue(seqAndCount1 in closedSeqs)

        closedSeq2 = ArrayList()
        closedSeq2.append(SequenceItem("A", 0))
        seqAndCount2 = FrequentSequence(closedSeq2, 6)
        self.assertTrue(seqAndCount2 in closedSeqs)

        closedSeq3 = ArrayList()
        closedSeq3.append(SequenceItem("A", 0))
        closedSeq3.append(SequenceItem("C", 2))
        seqAndCount3 = FrequentSequence(closedSeq3, 4)
        self.assertTrue(seqAndCount3 in closedSeqs)

    def test7(self):
        sequences = ArrayList()
        sequences.append(Sequence("ABCD", 2))
        sequences.append(Sequence("XBYD", 2))
        sequences.append(Sequence("AUCV", 2))
        sequences.append(Sequence("AAAA", 2))
        database = SequenceDatabase(sequences, 4)
        miner = ClosedSequenceMiner(database, 7)
        closedSeqs = miner.mineClosedSequences(None)
        self.assertEqual(0, len(closedSeqs))

    def test8(self):
        sequences = ArrayList()
        sequences.append(Sequence("ABCD", 2))
        sequences.append(Sequence("AABC", 2))
        sequences.append(Sequence("AAAB", 2))
        sequences.append(Sequence("AAAA", 2))
        database = SequenceDatabase(sequences, 4)
        miner = ClosedSequenceMiner(database, 3)
        closedSeqs = miner.mineClosedSequences(None)
        self.assertEqual(3, len(closedSeqs))

        closedSeq1 = ArrayList()
        closedSeq1.append(SequenceItem("A", 0))
        seqAndCount1 = FrequentSequence(closedSeq1, 8)
        self.assertTrue(seqAndCount1 in closedSeqs)

        closedSeq2 = ArrayList()
        closedSeq2.append(SequenceItem("A", 0))
        closedSeq2.append(SequenceItem("A", 1))
        seqAndCount2 = FrequentSequence(closedSeq2, 6)
        self.assertTrue(seqAndCount2 in closedSeqs)

        closedSeq3 = ArrayList()
        closedSeq3.append(SequenceItem("A", 0))
        closedSeq3.append(SequenceItem("A", 1))
        closedSeq3.append(SequenceItem("A", 2))
        seqAndCount3 = FrequentSequence(closedSeq3, 4)
        self.assertTrue(seqAndCount3 in closedSeqs)

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `ArrayList` and `SequenceItem`. You can use built-in list type or create your own class to represent these.