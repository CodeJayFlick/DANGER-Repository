import numpy as np

class MaskedSoftmaxCrossEntropyLoss:
    def __init__(self, name="MaskedSoftmaxCrossEntropyLoss", weight=1, class_axis=-1, sparse_label=True, from_logit=False):
        self.name = name
        self.weight = weight
        self.class_axis = class_axis
        self.sparse_label = sparse_label
        self.from_logit = from_logit

    def evaluate(self, labels, predictions):
        weights = np.ones_like(labels[0]) * (labels[1] > 0)
        pred = predictions if len(predictions) == 1 else [predictions][0]
        if not self.from_logit:
            pred = np.log(np.exp(pred) / np.sum(np.exp(pred), axis=self.class_axis, keepdims=True))
        
        loss = None
        lab = labels[0].reshape((-1,) + (pred.shape[1:]))
        if self.sparse_label:
            pick_index = [slice(None)] * len(lab.shape)
            pick_index[self.class_axis] = slice(None)
            for i in range(len(labels)):
                pick_index.append(slice(None) if lab[i][labels[1][i]] > 0 else np.newaxis)
            loss = -pred[tuple(pick_index)]
        else:
            loss = (lab * pred).sum(axis=self.class_axis, keepdims=True)

        loss *= weights
        return np.mean(loss)
