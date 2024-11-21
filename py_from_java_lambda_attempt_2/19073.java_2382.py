Here is the translation of the Java code into Python:

```Python
import unittest
from typing import List, Dict, Set, Any

class AbstractGlobalStates:
    def __init__(self, database_adapter: Any):
        self.database_adapter = database_adapter

    @staticmethod
    def catching_function(func) -> Any:
        try:
            return func()
        except RuntimeError as e:
            raise e
        except Exception as e:
            raise RuntimeError(e)

class GlobalStateParam:
    def __init__(self, branches: int = 1, commits_per_branch: int = 1, tables: int = 1,
                 table_commit_probability: float = 1.0):
        self.branches = branches
        self.commits_per_branch = commits_per_branch
        self.tables = tables
        self.table_commit_probability = table_commit_probability

    def __str__(self) -> str:
        return f"branches={self.branches}, commitsPerBranch={self.commits_per_branch}, " \
               f"tables={self.tables}, tableCommitProbability={self.table_commit_probability}"

def global_states_params() -> List[GlobalStateParam]:
    return [
        GlobalStateParam(1, 1, 1),
        GlobalStateParam(3, 3, 3),
        # Forces multiple global_log entries
        GlobalStateParam(1, 500, 1),
        GlobalStateParam(tables=1000, commits_per_branch=100, table_commit_probability=.05),
        GlobalStateParam(branches=3, tables=1000, commits_per_branch=100, table_commit_probability=.01),
        GlobalStateParam(branches=3, tables=100, commits_per_branch=1000, table_commit_probability=.01),
        GlobalStateParam(1, 30, 30, .4)
    ]

class TestAbstractGlobalStates(unittest.TestCase):
    def test_global_states(self) -> None:
        for param in global_states_params():
            branches = [f"global-states-{i}" for i in range(param.branches)]
            heads = {branch: self.database_adapter.create(branch, self.database_adapter.to_hash("main")) 
                    for branch in branches}
            current_states = {}
            keys = set(f"table{i}" for i in range(param.tables))
            used_content_ids = set()

            expected_global_states = {}
            expected_contents = {}

            for _ in range(param.commits_per_branch):
                for branch in branches:
                    commit_attempt = ImmutableCommitAttempt.builder() \
                        .commit_to_branch(branch) \
                        .expected_head(Optional.of(heads[branch])) \
                        .commit_meta_serialized("some commit#{} branch {}".format(_, branch)) \
                        .build()

                    for key in keys:
                        if param.table_commit_probability == 1.0 or ThreadLocalRandom.current().next_double(0, 1) <= param.table_commit_probability:
                            state = f"state-commit-{_}+{key}"
                            value = f"value-commit-{_}+{key}"
                            contents_id = ContentsId(f"{key}-{branch}")
                            put = ByteString.from_utf8(value)
                            global_state = ByteString.from_utf8(state)

                            commit_attempt.put_expected_states(contents_id, Optional.ofNullable(current_states.get(contents_id)))
                            commit_attempt.put_global(contents_id, global_state)
                            commit_attempt.add_puts(KeyWithBytes(key, contents_id, 0, put))

                            expected_global_states[contents_id] = global_state

                            expected_contents.setdefault(KeyWithType(f"{key}-{branch}", 0), []).append(put)

                            used_content_ids.add(contents_id)
                            current_states[contents_id] = global_state
                    if not commit_attempt.get_puts().empty:
                        heads[branch] = self.database_adapter.commit(commit_attempt)

            with Stream(self.database_adapter.global_keys(lambda x: 0)) as stream:
                self.assertSetEqual({k.contents_id for k in stream}, expected_global_states.keys())

            with Stream(self.database_adapter.global_contents(expected_global_states.keys(), lambda s: 0)) as stream:
                all = list(stream.collect(Collectors.toList()))
                self.assertEqual(len(all), len(used_content_ids))
                self.assertEqual(set(k.contents_id for k, _ in all), used_content_ids)
                self.assertEqual({k.contents_id for k, v in all}, current_states.keys())
                self.assertEqual([v for _, v in all], list(expected_global_states.values()))

    def test_commit_check_global_state_mismatches(self) -> None:
        branch = "main"
        initial_branch_hash = self.database_adapter.to_hash(branch)

        commit_attempt = ImmutableCommitAttempt.builder() \
            .commit_to_branch(branch) \
            .expected_head(Optional.of(initial_branch_hash)) \
            .commit_meta_serialized(ByteString.EMPTY) \
            .add_puts(KeyWithBytes("my", "table", "num0", ContentsId("id-0"), 0, ByteString.from_utf8("there"))) \
            .put_global(ContentsId("id-0"), ByteString.from_utf8("global")) \
            .build()

        self.assertRaises(ReferenceConflictException,
                            lambda: self.database_adapter.commit(commit_attempt))

        commit_attempt = ImmutableCommitAttempt.builder() \
            .commit_to_branch(branch) \
            .expected_head(Optional.of(initial_branch_hash)) \
            .commit_meta_serialized(ByteString.EMPTY) \
            .add_puts(KeyWithBytes("my", "table", "num0", ContentsId("id-NOPE"), 0, ByteString.from_utf8("no no"))) \
            .put_global(ContentsId("id-NOPE"), ByteString.from_utf8("DUPLICATE")) \
            .build()

        self.assertRaises(ReferenceConflictException,
                            lambda: self.database_adapter.commit(commit_attempt))

    def test_commit_check_global_state_mismatches(self) -> None:
        branch = "main"
        initial_branch_hash = self.database_adapter.to_hash(branch)

        commit_attempt = ImmutableCommitAttempt.builder() \
            .commit_to_branch(branch) \
            .expected_head(Optional.of(initial_branch_hash)) \
            .commit_meta_serialized(ByteString.EMPTY) \
            .add_puts(KeyWithBytes("my", "table", "num0", ContentsId("id-NOPE"), 0, ByteString.from_utf8("no no"))) \
            .put_global(ContentsId("id-NOPE"), ByteString.from_utf8("DUPLICATE")) \
            .build()

        self.assertRaises(ReferenceConflictException,
                            lambda: self.database_adapter.commit(commit_attempt))

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The original Java code uses various libraries like Apache Commons Lang, Google Protocol Buffers, etc., which are not directly available in Python. Therefore, some parts might need to be rewritten or replaced with equivalent Python functions.