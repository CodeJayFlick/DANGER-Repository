Here is the translation of the Java code into Python:

```Python
import os
from typing import List

class StanfordMovieReview:
    def __init__(self):
        self.review_sentiments = []
        self.review_imdb_score = []

    @classmethod
    def builder(cls) -> 'Builder':
        return cls.Builder()

    class Builder:
        def __init__(self):
            pass

        def build(self) -> 'StanfordMovieReview':
            return StanfordMovieReview()

        def prepare(self, progress: callable) -> None:
            if not hasattr(StanfordMovieReview(), 'prepared'):
                artifact = MRL().get_default_artifact()
                MRL().prepare(artifact, progress)
                cache_dir = MRL().getRepository().get_cache_directory()
                resource_uri = artifact.get_resource_uri()
                root = os.path.join(cache_dir, resource_uri.path, "aclImdb", "aclImdb")

                usage_path = None
                if self.usage == 'TRAIN':
                    usage_path = os.path.join(root, "train")
                elif self.usage == 'TEST':
                    usage_path = os.path.join(root, "test")
                else:
                    raise ValueError("Validation data not available.")

                review_texts = []
                for sentiment in [True, False]:
                    path = os.path.join(usage_path, "pos" if sentiment else "neg")
                    prepare_data_sentiment(path, sentiment, review_texts)

                preprocess(review_texts)
                setattr(StanfordMovieReview(), 'prepared', True)

        def get(self) -> Record:
            data = []
            for i in range(len(self.review_sentiments)):
                data.append(source_text_data.get(i))
            label = [int(sentiment) for sentiment in self.review_sentiments]
            return Record(data, label)

        @property
        def available_size(self):
            return len(self.review_sentiments)


class MRL:
    @classmethod
    def get_default_artifact(cls) -> 'Artifact':
        pass

    @classmethod
    def prepare(cls, artifact: Artifact, progress: callable) -> None:
        pass


class Record:
    def __init__(self, data: List, label: List):
        self.data = data
        self.label = label


def prepare_data_sentiment(path: str, sentiment: bool, review_texts: List) -> None:
    if not os.path.exists(path):
        raise ValueError("Could not find Stanford Movie Review dataset")
    files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
    for file in files:
        path_file = os.path.join(path, file)
        review_text = open(path_file, 'r').read()
        split_name = file.split('.')[0].split('_')
        review_texts.append(review_text)
        sentiment_list = [sentiment] * len(files)
        imdb_score = [int(score) for score in split_name[1]]
        return


def preprocess(review_texts: List) -> None:
    pass
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The `MRL`, `Artifact` classes are placeholders as they were not provided with their implementation in the original Java code.