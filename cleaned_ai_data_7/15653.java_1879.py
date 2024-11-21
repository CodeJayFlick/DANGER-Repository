import numpy as np

class TopKAccuracy:
    def __init__(self, name="Top_K_Accuracy", index=0, top_k=1):
        self.name = name
        self.index = index
        if top_k > 1:
            self.top_k = top_k
        else:
            raise ValueError("Please use TopKAccuracy with top_k more than 1")

    def accuracy_helper(self, labels, predictions):
        label = labels[self.index]
        prediction = predictions[self.index]

        # number of labels and predictions should be the same
        if len(label.shape) > 0 and len(prediction.shape) > 0:
            check_label_shapes(label, prediction)

        top_k_prediction = np.argsort(prediction)[::-1][:self.top_k]
        num_correct = (prediction[top_k_prediction] == label).sum()

        total = label.shape[0]
        return {"total": total, "num_correct": num_correct}

def check_label_shapes(label, prediction):
    if len(label.shape) > 0 and len(prediction.shape) > 0:
        pass
    else:
        raise ValueError("Number of labels and predictions should be the same")

# Example usage:

top_k_accuracy = TopKAccuracy(index=0, top_k=5)
labels = np.random.randint(0, 10, (100,))
predictions = np.random.randint(0, 10, (100,))
result = top_k_accuracy.accuracy_helper(labels, predictions)

print(result["total"])
print(result["num_correct"])
