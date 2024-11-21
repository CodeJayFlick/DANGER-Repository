import numpy as np

class SoftmaxCrossEntropyLoss:
    def __init__(self):
        self.weight = 1
        self.class_axis = -1
        self.sparse_label = True
        self.from_logit = True

    def evaluate(self, label, prediction):
        pred = prediction[0]
        if self.from_logit:
            pred = np.log(pred) / np.sum(np.exp(np.log(pred)), axis=self.class_axis)
        
        loss = None
        lab = label[0].flatten()
        if self.sparse_label:
            pick_index = [slice(None)] * len(lab.shape)
            pick_index[self.class_axis] = slice(0, 1)
            loss = -pred[tuple(pick_index)]
        else:
            lab = lab.reshape(pred.shape)
            loss = np.sum(-lab * pred, axis=self.class_axis)

        if self.weight != 1:
            loss *= self.weight
        
        return np.mean(loss)
