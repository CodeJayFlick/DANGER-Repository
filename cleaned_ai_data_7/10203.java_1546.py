class JsonError:
    SUCCESS = "Everything was fine"
    NOMEM = "Not enough tokens were provided"
    INVAL = "Invalid character inside JSON string"
    PART = "The string is not a full JSON packet, more bytes expected"

JSONError = type('JSONError', (), dict.fromkeys(locals().values()))
