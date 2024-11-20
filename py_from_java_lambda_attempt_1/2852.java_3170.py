Here is the translation of the Java code to Python:
```
import collections

class LanguageCompilerSpecPair:
    def __init__(self, language_id, compiler_spec_id):
        self.language_id = language_id
        self.compiler_spec_id = compiler_spec_id

def get_all_pairs_for_languages(language_ids):
    result = set()
    lang_serv = DefaultLanguageService().get_language_service()

    for lid in language_ids:
        l = lang_serv.get_language(lid)
        for csd in l.get_compatible_compiler_spec_descriptions():
            result.add(LanguageCompilerSpecPair(lid, csd.get_compiler_spec_id()))
    
    return result

def get_all_pairs_for_language(language):
    return get_all_pairs_for_languages({language})

class DefaultLanguageService:
    @staticmethod
    def get_language_service():
        # implement this method to return the language service instance
        pass

# usage example
if __name__ == "__main__":
    lang_serv = DefaultLanguageService().get_language_service()
    all_pairs = get_all_pairs_for_languages({lang_serv.get_language("some_lang_id")})
    print(all_pairs)
```
Note that I had to make some assumptions about the `DefaultLanguageService` class, as it was not provided in the original Java code. In Python, we don't have a direct equivalent of Java's static methods, so I wrapped them inside classes for consistency and readability.