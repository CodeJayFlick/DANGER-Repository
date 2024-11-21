import numpy as np
from scipy.special import softmax
from sklearn.metrics import log_loss

class LossTest:
    def l1LossTest(self):
        pred = np.array([1, 2, 3, 4, 5])
        label = np.ones(5)
        assert np.isclose(Loss.l1().evaluate(label, pred), 2.0)

    def l2LossTest(self):
        pred = np.array([1, 2, 3, 4, 5])
        label = np.ones(5)
        assert np.isclose(Loss.l2().evaluate(label, pred), 3.0)

    def softmaxCrossEntropyTest(self):
        # test fromLogits=TRUE, sparseLabel=TRUE
        pred = np.array([1, 2, 3, 4, 5])
        label = np.ones(1)
        assert np.isclose(Loss.softmaxCrossEntropy("loss", 1, -1, True, True).evaluate(label, pred), 3.45191431)

        # test fromLogits=FALSE, sparseLabel=TRUE
        pred = np.array([[4.0, 2.0, 1.0], [0.0, 5.0, 1.0]])
        label = np.ones(2)
        nonSparseLabel = np.zeros((2, 3))
        nonSparseLabel[0] = 1
        sparseOutput = Loss.softmaxCrossEntropy().evaluate([label], pred.logSoftmax(-1))
        assert np.isclose(sparseOutput, log_loss(label.reshape(-1), pred.flatten(), normalize=True))

        # test fromLogits=FALSE, sparseLabel=FALSE
        nonSparseOutput = Loss.softmaxCrossEntropy("loss", 1, -1, False, False).evaluate([nonSparseLabel], pred.logSoftmax(-1))
        assert np.isclose(sparseOutput, nonSparseOutput)
        assert np.isclose(nonSparseOutput, log_loss(label.reshape(-1), pred.flatten(), normalize=True))

    def hingeLossTest(self):
        pred = np.array([1, 2, 3, 4, 5])
        label = -np.ones(5)
        assert np.isclose(Loss.hinge().evaluate(label, pred), 4.0)

    def sigmoidBinaryCrossEntropyLossTest(self):
        pred = np.array([1, 2, 3, 4, 5])
        label = np.ones(5)
        assert np.isclose(Loss.sigmoidBinaryCrossEntropy().evaluate(label, pred), 0.10272846)

    def maskedSoftmaxCrossEntropyLossTest(self):
        pred = np.ones((3, 4, 10))
        label = np.ones((3, 4))
        validLengths = [4, 2, 0]
        assert np.isclose(Loss.maskedSoftmaxCrossEntropy().evaluate([label], [pred]), [[2.3025851], [1.1512926], [0]])


# Usage:
test = LossTest()
test.l1LossTest()
test.l2LossTest()
test.softmaxCrossEntropyTest()
test.hingeLossTest()
test.sigmoidBinaryCrossEntropyLossTest()
test.maskedSoftmaxCrossEntropyLossTest()

