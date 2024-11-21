Here is the translation of the Java code into Python:

```Python
class NonTransactionalDatabaseAdapter:
    def __init__(self):
        pass

    @staticmethod
    def hash_on_reference(ctx: 'NonTransactionalOperationContext', ref: NamedRef, expected_hash: Optional[Hash]) -> Hash:
        return ctx.hash_on_ref(ref, expected_hash)

    @staticmethod
    def cas_op_loop(ctx: 'NonTransactionalOperationContext', op_variant: CasOpVariant, cas_op: 'CasOp', retry_error_message_supplier: Supplier[str]) -> Hash:
        try_state = new_try_loop_state(retry_error_message_supplier)
        while True:
            pointer = ctx.fetch_global_pointer()
            individual_commits = set()
            individual_key_lists = set()

            new_pointer = cas_op.apply(ctx, pointer, lambda x: individual_commits.add(x), lambda x: individual_key_lists.add(x))
            if new_pointer.global_id == pointer.global_id:
                return try_state.success(branch_head(new_pointer, ref))

            hash_collision_detected()
            try_state.retry()

    @staticmethod
    def write_global_commit(ctx: 'NonTransactionalOperationContext', time_in_micros: int, parent_hash: Hash, globals: List[Hash]) -> Hash:
        current_entry = ctx.fetch_from_global_log(parent_hash)
        new_parents = set([parent_hash])
        if current_entry is not None:
            new_parents.update(current_entry.parents_list().stream().limit(config.get_parent_per_global_commit() - 1).map(lambda x: Hash(x)))

        hash = random_hash()
        entry_builder = GlobalStateLogEntry.newBuilder().set_created_time(time_in_micros).set_id(hash.as_bytes())
        new_parents.forEach(lambda p: entry_builder.add_parents(p.as_bytes()))
        globals.forEach(lambda g: entry_builder.add_puts(ProtoSerialization.to_proto(g)))
        ctx.write_global_commit(entry.build())

        return hash

    @staticmethod
    def global_pointer_cas(ctx: 'NonTransactionalOperationContext', expected: GlobalStatePointer, new_pointer: GlobalStatePointer) -> bool:
        pass  # implementation specific

    @staticmethod
    def clean_up_commit_cas(ctx: 'NonTransactionalOperationContext', global_id: Hash, branch_commits: Set[Hash], new_key_lists: Set[Hash]) -> None:
        pass  # implementation specific

    @staticmethod
    def noop_global_log_entry(ctx: 'NonTransactionalOperationContext', pointer: GlobalStatePointer) -> Hash:
        return ctx.write_global_commit(0, Hash(pointer.global_id), [])

    @staticmethod
    def branch_head(pointer: GlobalStatePointer, ref: NamedRef) -> Hash:
        if not isinstance(ref, (BranchName, TagName):
            raise ReferenceNotFoundException(f"Reference {ref} does not exist.")

        return Hash(to_named_ref(type=pointer.named_references_map().get(ref.name))

    @staticmethod
    def fetch_global_pointer(ctx: 'NonTransactionalOperationContext') -> GlobalStatePointer:
        pass  # implementation specific

class CasOp:
    def apply(self, ctx: 'NonTransactionalOperationContext', pointer: GlobalStatePointer) -> Hash:
        pass  # implementation specific


def new_try_loop_state(retry_error_message_supplier):
    try_state = TryLoopState()
    return try_state
```

Please note that this is a direct translation of the Java code into Python, and it may not work as expected.