Here is the equivalent Python code:

```Python
class ProgramTask:
    def __init__(self, program: 'Program', title: str, can_cancel: bool = False,
                 has_progress: bool = True, is_modal: bool = False):
        self.program = program
        super().__init__(title=title, can_cancel=can_cancel, has_progress=has_progress,
                          is_modal=is_modal)

    def run(self) -> None:
        try:
            do_run()
            commit_transaction()
        except RollbackException as e:
            print(f"Task Failed - {self.title} ({e})")
        except Exception as e:
            print(f"Task failed - {self.title}")
            raise
        finally:
            end_transaction()

    def do_run(self) -> None:
        # This method should be implemented by the subclass.
        pass

def start_transaction(title: str) -> int:
    return 0  # Replace with actual implementation.

def commit_transaction() -> None:
    print("Commit transaction")

def rollback_transaction(transaction_id: int, did_commit: bool = False) -> None:
    if not did_commit:
        print(f"Rollback transaction {transaction_id}")
```

Note that Python does not have direct equivalent of Java's `abstract` keyword. Instead, you can define an abstract method by giving it a name starting with `_`.