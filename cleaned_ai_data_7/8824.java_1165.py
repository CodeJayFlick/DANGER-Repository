class VTMatchInfo:
    def __init__(self, match_set):
        self.match_set = match_set
        self.association_type = None
        self.tag = None
        self.similarity_score = 0.0
        self.confidence_score = 0.0
        self.source_address = None
        self.destination_address = None
        self.source_length = 0
        self.destination_length = 0

    def get_match_set(self):
        return self.match_set

    def set_association_type(self, association_type):
        self.association_type = association_type

    def get_association_type(self):
        return self.association_type

    def set_tag(self, tag):
        self.tag = tag

    def get_tag(self):
        return self.tag

    def set_similarity_score(self, score):
        self.similarity_score = score

    def get_similarity_score(self):
        return self.similarity_score

    def set_confidence_score(self, score):
        self.confidence_score = score

    def get_confidence_score(self):
        return self.confidence_score

    def set_source_address(self, address):
        self.source_address = address

    def get_source_address(self):
        return self.source_address

    def set_destination_address(self, address):
        self.destination_address = address

    def get_destination_address(self):
        return self.destination_address

    def set_source_length(self, length):
        self.source_length = length

    def get_source_length(self):
        return self.source_length

    def set_destination_length(self, length):
        self.destination_length = length

    def get_destination_length(self):
        return self.destination_length

    def __hash__(self):
        if self.source_address is not None:
            return hash(self.source_address.get_offset())
        else:
            return 0

    def __eq__(self, other):
        if self == other:
            return True
        elif other is None:
            return False
        elif not isinstance(other, VTMatchInfo):
            return False

        other = VTMatchInfo(other)
        if self.destination_length != other.get_destination_length():
            return False
        if self.association_type != other.get_association_type():
            return False
        if self.similarity_score != other.get_similarity_score():
            return False
        if self.confidence_score != other.get_confidence_score():
            return False
        if self.source_length != other.get_source_length():
            return False
        if self.tag != other.get_tag():
            return False

        return True

    def __str__(self):
        buffer = ""
        sim_score_value = 0.0 if self.similarity_score is None else self.similarity_score.score
        conf_score_value = 0.0 if self.confidence_score is None else self.confidence_score.score
        buffer += "MatchInfo: \n"
        buffer += f" Type               ={self.get_association_type()}\n"
        buffer += f" Similarity Score   ={sim_score_value}\n"
        buffer += f" Confidence Score   ={conf_score_value}\n"
        buffer += f" SourceAddress      ={self.source_address}\n"
        buffer += f" DestinationAddress ={self.destination_address}\n"
        buffer += f" SourceLength       ={self.source_length}\n"
        buffer += f" DestinationLength  ={self.destination_length}\n"
        buffer += f" Tagged             ={self.tag}\n"
        return buffer
