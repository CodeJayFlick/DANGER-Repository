Here is the translation of the Java code to Python:

```Python
import os
from collections import defaultdict

class StringModel:
    def __init__(self):
        self.ascii_trigram_storage = [[[0 for _ in range(128)] for _ in range(128)] for _ in range(128)]
        self.begin_string_trigram_storage = [[0 for _ in range(128)] for _ in range(128)]
        self.end_string_trigram_storage = [[0 for _ in range(128)] for _ in range(128)]
        self.total_num_trigrams = 0
        self.ascii_num_to_description = defaultdict(list)
        self.text_reps = [None] * 128

    def set_ascii_trigram(self, ascii_trigrams):
        self.ascii_trigram_storage = ascii_trigrams

    def get_ascii_trigram(self):
        return self.ascii_trigram_storage

    def set_begin_string_trigram(self, begin_trigram):
        self.begin_string_trigram_storage = begin_trigram

    def get_begin_string_trigram(self):
        return self.begin_string_trigram_storage

    def set_end_string_trigram(self, end_trigram):
        self.end_string_trigram_storage = end_trigram

    def get_end_string_trigram(self):
        return self.end_string_trigram_storage

    def set_total_num_trigrams(self, num_trigrams):
        self.total_num_trigrams = num_trigrams

    def get_total_num_trigrams(self):
        return self.total_num_trigrams

    def write_trigram_model_file(self, trigram_filename, training_files, model_type, output_path):
        try:
            with open(os.path.join(output_path, trigram_filename), 'w') as f:
                f.write("# Model Type: " + model_type)
                f.write("\n")
                for file in training_files:
                    f.write("# Training file: " + file)
                    f.write("\n")

                f.write("# [^] denotes beginning of string\n")
                f.write("# [$] denotes end of string\n")
                f.write("\n")

                comments_needed = set()
                for i in range(128):
                    for j in range(128):
                        for k in range(128):
                            if self.ascii_trigram_storage[i][j][k] > 0:
                                if i < 33 or (i >= 127 and i <= 159) or (i >= 160 and i <= 173) or (i == 181) or (i >= 192 and i <= 223):
                                    comments_needed.add(i)
                                elif j < 33 or (j >= 127 and j <= 159) or (j >= 160 and j <= 173) or (j == 181) or (j >= 192 and j <= 223):
                                    comments_needed.add(j)
                                elif k < 33 or (k >= 127 and k <= 159) or (k >= 160 and k <= 173) or (k == 181) or (k >= 192 and k <= 223):
                                    comments_needed.add(k)

                for ascii_num in sorted(comments_needed, reverse=True):
                    char_details = self.ascii_num_to_description[ascii_num]
                    f.write("# " + char_details[0] + " denotes " + char_details[1])
                    f.write("\n")
                f.write("\n")

                for i in range(128):
                    for j in range(128):
                        if self.begin_string_trigram_storage[i][j] > 0:
                            f.write("[^]\t" + chr(i) + "\t" + chr(j) + "\t" + str(self.begin_string_trigram_storage[i][j]))
                            f.write("\n")
                for i in range(128):
                    for j in range(128):
                        if self.end_string_trigram_storage[i][j] > 0:
                            f.write(chr(i) + "\t" + chr(j) + "\t[$]\t" + str(self.end_string_trigram_storage[i][j]))
                            f.write("\n")
        except Exception as e:
            print("Error creating String Model file: " + str(e))
```

Please note that Python does not support exact equivalent of Java's HashMap and HashSet. Instead, we use a dictionary (defaultdict) to store the ASCII number to description mapping.