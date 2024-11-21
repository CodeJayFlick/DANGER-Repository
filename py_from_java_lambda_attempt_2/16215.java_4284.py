Here is the translation of the Java code into equivalent Python:

```Python
class FtTrainingConfig:
    def __init__(self, builder):
        self.training_mode = builder.training_mode
        self.output_dir = builder.output_dir
        self.model_name = builder.model_name
        self.epoch = builder.epoch
        self.min_word_count = builder.min_word_count
        self.min_label_count = builder.min_label_count
        self.max_ngram_length = builder.max_ngram_length
        self.min_char_length = builder.min_char_length
        self.max_char_length = builder.max_char_length
        self.bucket = builder.bucket
        self.sampling_threshold = builder.sampling_threshold
        self.label_prefix = builder.label_prefix
        self.learning_rate = builder.learning_rate
        self.learning_rate_update_rate = builder.learning_rate_update_rate
        self.word_vec_size = builder.word_vec_size
        self.context_window = builder.context_window
        self.num_negatives_sampled = builder.num_negatives_sampled
        self.threads = builder.threads
        self.loss = builder.loss

    def get_training_mode(self):
        return self.training_mode

    def get_output_dir(self):
        return self.output_dir

    def get_model_name(self):
        return self.model_name

    def get_epoch(self):
        return self.epoch

    def get_min_word_count(self):
        return self.min_word_count

    def get_min_label_count(self):
        return self.min_label_count

    def get_max_ngram_length(self):
        return self.max_ngram_length

    def get_min_char_length(self):
        return self.min_char_length

    def get_max_char_length(self):
        return self.max_char_length

    def get_bucket(self):
        return self.bucket

    def get_sampling_threshold(self):
        return self.sampling_threshold

    def get_label_prefix(self):
        return self.label_prefix

    def get_learning_rate(self):
        return self.learning_rate

    def get_learning_rate_update_rate(self):
        return self.learning_rate_update_rate

    def get_word_vec_size(self):
        return self.word_vec_size

    def get_context_window(self):
        return self.context_window

    def get_num_negatives_sampled(self):
        return self.num_negatives_sampled

    def get_threads(self):
        return self.threads

    def get_loss(self):
        return self.loss


class FtTrainingConfigBuilder:
    def __init__(self):
        self.training_mode = 'SUPERVISED'
        self.output_dir = None
        self.model_name = ''
        self.epoch = 5
        self.min_word_count = 1
        self.min_label_count = 0
        self.max_ngram_length = 1
        self.min_char_length = 0
        self.max_char_length = 0
        self.bucket = 2000000
        self.sampling_threshold = 0.0001
        self.label_prefix = '__lable__'
        self.learning_rate = 0.1
        self.learning_rate_update_rate = 100
        self.word_vec_size = 100
        self.context_window = 5
        self.num_negatives_sampled = 5
        self.threads = 12
        self.loss = 'SOFTMAX'

    def set_output_dir(self, output_dir):
        self.output_dir = output_dir
        return self

    def set_model_name(self, model_name):
        self.model_name = model_name
        return self

    def set_training_mode(self, training_mode):
        self.training_mode = training_mode
        return self

    def set_epoch(self, epoch):
        self.epoch = epoch
        return self

    def set_min_word_count(self, min_word_count):
        self.min_word_count = min_word_count
        return self

    def set_min_label_count(self, min_label_count):
        self.min_label_count = min_label_count
        return self

    def set_max_ngram_length(self, max_ngram_length):
        self.max_ngram_length = max_ngram_length
        return self

    def set_min_char_length(self, min_char_length):
        self.min_char_length = min_char_length
        return self

    def set_max_char_length(self, max_char_length):
        self.max_char_length = max_char_length
        return self

    def set_bucket(self, bucket):
        self.bucket = bucket
        return self

    def set_sampling_threshold(self, sampling_threshold):
        self.sampling_threshold = sampling_threshold
        return self

    def set_label_prefix(self, label_prefix):
        self.label_prefix = label_prefix
        return self

    def set_learning_rate(self, learning_rate):
        self.learning_rate = learning_rate
        return self

    def set_learning_rate_update_rate(self, learning_rate_update_rate):
        self.learning_rate_update_rate = learning_rate_update_rate
        return self

    def set_word_vec_size(self, word_vec_size):
        self.word_vec_size = word_vec_size
        return self

    def set_context_window(self, context_window):
        self.context_window = context_window
        return self

    def set_num_negatives_sampled(self, num_negatives_sampled):
        self.num_negatives_sampled = num_negatives_sampled
        return self

    def set_threads(self, threads):
        self.threads = threads
        return self

    def set_loss(self, loss):
        self.loss = loss
        return self

    def build(self):
        return FtTrainingConfig(self)
```

Note that Python does not have an exact equivalent to Java's enum type. Instead, you can use a class with static methods or constants for the different loss functions.