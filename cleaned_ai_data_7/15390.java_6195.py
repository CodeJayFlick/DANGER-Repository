class Application:
    UNDEFINED = "undefined"

    def __init__(self, path):
        self.path = path

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value

    def __str__(self):
        return self.path.replace('/', '.').upper()

    def matches(self, test):
        if isinstance(test, Application):
            return self.path.startswith(test.path)
        else:
            raise ValueError("test must be an instance of Application")

    def __eq__(self, other):
        if not isinstance(other, Application):
            return False
        return self.path == other.path

    def __hash__(self):
        return hash(self.path)

class CV(Application):
    ANY = "cv"
    IMAGE_CLASSIFICATION = "cv/image_classification"
    OBJECT_DETECTION = "cv/object_detection"
    SEMANTIC_SEGMENTATION = "cv/semantic_segmentation"
    INSTANCE SEGMENTATION = "cv/instance_segmentation"
    POSE_ESTIMATION = "cv/pose_estimation"
    ACTION_RECOGNITION = "cv/action_recognition"
    WORD_RECOGNITION = "cv/word_recognition"
    IMAGE_GENERATION = "cv/image_generation"
    IMAGE_ENHANCEMENT = "cv/image_enhancement"

class NLP(Application):
    ANY = "nlp"
    QUESTION_ANSWER = "nlp/question_answer"
    TEXT_CLASSIFICATION = "nlp/text_classification"
    SENTIMENT_ANALYSIS = "nlp/sentiment_analysis"
    WORD_EMBEDDING = "nlp/word_embedding"
    MACHINE_TRANSLATION = "nlp/machine_translation"
    MULTIPLE_CHOICE = "nlp/multiple_choice"

class Tabular(Application):
    ANY = "tabular"
    LINEAR_REGRESSION = "tabular/linear_regression"
