class Finders:
    def __init__(self):
        pass


def advanced_finder(query: str, or_query: str = None, not_query: str = None) -> callable:
    if not_query:
        return lambda txt: [word for word in txt.split() if word != not_query] and [word for word in txt.split() if word == query or word == or_query]
    else:
        return lambda txt: [word for word in txt.split() if word == query]


def filtered_finder(query: str, *exclude_queries) -> callable:
    finder = advanced_finder(query)
    
    for q in exclude_queries:
        finder = lambda txt: [word for word in txt.split() if word != q] and finder(txt)

    return finder


def specialized_finder(*queries) -> callable:
    finder = lambda txt: []
    
    for query in queries:
        finder = lambda txt: [word for word in txt.split() if word == query] + finder(txt)
        
    return finder


def expanded_finder(*queries) -> callable:
    finder = lambda txt: []

    for query in queries:
        finder = lambda txt: [word for word in txt.split() if word == query] or finder(txt)

    return finder
