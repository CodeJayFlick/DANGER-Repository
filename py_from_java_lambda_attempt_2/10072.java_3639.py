Here is the translation of the Java code to Python:
```
import serializable

class GhidraPrincipal(serializable.Serializable):
    def __init__(self, username: str) -> None:
        self.username = username

    @property
    def name(self) -> str:
        return self.username

    @classmethod
    def get_ghidra_principal(cls, subj: 'Subject') -> 'GhidraPrincipal':
        if subj is not None:
            principals = list(subj.get_principals().values())
            if principals:
                return next(iter(principals))
        return None


class Subject:
    def __init__(self) -> None:
        self.principals: dict[type, set] = {}

    def get_principals(self) -> dict[type, set]:
        return self.principals

    def add_principal(self, principal: 'GhidraPrincipal') -> None:
        if not isinstance(principal, GhidraPrincipal):
            raise ValueError("Invalid principal")
        self.principals.setdefault(type(GhidraPrincipal), set()).add(principal)
```
Note that I had to create a `Subject` class in Python since there is no equivalent built-in type. Also, the `serialVersionUID` field has been removed as it's not necessary in Python.

Also, please note that this translation assumes that you want to keep the same functionality and structure of the original Java code. If you need any modifications or simplifications, let me know!