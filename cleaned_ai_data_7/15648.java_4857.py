class BinaryAccuracy:
    def __init__(self, name="BinaryAccuracy", threshold=0.5, index=0):
        self.threshold = threshold
        self.index = index
        self.name = name

    @staticmethod
    def accuracy_helper(labels, predictions):
        if len(labels) != len(predictions):
            raise ValueError("labels and prediction length does not match.")
        
        label_array = labels[index]
        pred_array = predictions[index]

        total = len(label_array)
        correct_count = (label_array == 1) & ((pred_array >= threshold).astype(int)).sum()
        
        return total, correct_count

# Example usage:
labels = [[0, 1], [0, 1]]
predictions = [[0.5, 0.7], [0.3, 0.9]]

accuracy_evaluator = BinaryAccuracy(threshold=0.5)
total_correct, _ = accuracy_evaluator.accuracy_helper(labels, predictions)

print(f"Total correct: {total_correct}")
