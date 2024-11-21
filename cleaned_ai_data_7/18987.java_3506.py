class TreeApiImpl:
    def __init__(self, config: 'ServerConfig', store: 'VersionStore[Contents, CommitMeta, Contents.Type]', access_checker: 'AccessChecker', principal: 'Principal'):
        super().__init__(config, store, access_checker, principal)

    @staticmethod
    def make_named_ref(ref_with_hash):
        return TreeApiImpl.make_ref(ref_with_hash)

    @staticmethod
    def make_ref(ref_with_hash):
        ref = ref_with_hash.value
        if isinstance(ref, TagName):
            return ImmutableTag(builder=lambda: ImmutableTag(name=ref.name, hash=str(ref_with_hash.hash)))
        elif isinstance(ref, BranchName):
            return ImmutableBranch(builder=lambda: ImmutableBranch(name=ref.name, hash=str(ref_with_hash.hash)))
        else:
            raise NotImplementedError("only converting tags or branches")

    def get_all_references(self) -> List['Reference']:
        try:
            with self.get_store().get_named_refs() as named_ref_stream:
                return list(map(lambda x: TreeApiImpl.make_named_ref(x), named_ref_stream))
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(str(e))

    def get_reference_by_name(self, ref_name: str) -> 'Reference':
        try:
            reference = self.get_store().to_ref(ref_name)
            return make_ref(reference)
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(str(e), e)

    def create_reference(self, source_ref_name: str, reference: 'Reference') -> 'Reference':
        if isinstance(reference, Branch):
            named_reference = BranchName.of(reference.name)
            hash = self.create_reference(named_reference, reference.hash)
            return Branch.of(reference.name, hash.as_string())
        elif isinstance(reference, Tag):
            named_reference = TagName.of(reference.name)
            hash = self.create_reference(named_reference, reference.hash)
            return Tag.of(reference.name, hash.as_string())
        else:
            raise ValueError("Only tag and branch references can be created.")

    def assign_tag(self, tag_name: str, expected_hash: str, assign_to: 'Reference') -> None:
        self.assign_reference(TagName.of(tag_name), expected_hash, assign_to)

    def delete_tag(self, tag_name: str, hash: str) -> None:
        self.delete_reference(TagName.of(tag_name), hash)

    def assign_branch(self, branch_name: str, expected_hash: str, assign_to: 'Reference') -> None:
        self.assign_reference(BranchName.of(branch_name), expected_hash, assign_to)

    def delete_branch(self, branch_name: str, hash: str) -> None:
        self.delete_reference(BranchName.of(branch_name), hash)

    def get_commit_log(self, named_ref: str, params: 'CommitLogParams') -> 'ImmutableLogResponse':
        max_entries = min(params.max_records() if params.max_records() is not None else 250, 250)
        end_ref = self.named_ref_with_hash_or_throw(named_ref, params.page_token()) if params.page_token() is not None else self.get_store().to_ref(named_ref).get_hash()
        try:
            with self.get_store().get_commits(end_ref) as commit_stream:
                stream = StreamSupport.stream(StreamUtil.take_until_incl(commit_stream.map(lambda x: ImmutableCommitMeta(builder=lambda: ImmutableCommitMeta(hash=str(x.hash))), end_func=lambda x: x.hash == params.start_hash()), False)
                items = list(filter_commit_log(stream, params.query_expression()).limit(max_entries + 1).collect(Collectors.toList()))
                if len(items) == max_entries + 1:
                    return ImmutableLogResponse.builder().addAll_operations(items[:max_entries]).is_has_more(True).token(items[-1].hash).build()
                else:
                    return ImmutableLogResponse(builder=lambda: ImmutableLogResponse().addAll_operations(items)).build()
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(str(e))

    def filter_commit_log(self, stream: Stream['ImmutableCommitMeta'], query_expression: str) -> Stream['ImmutableCommitMeta']:
        if not query_expression:
            return stream
        script = self.script_host().build_script(query_expression).with_container(self.container()).with_declarations(self.commit_log_declarations())
        try:
            return stream.filter(lambda x: script.execute(bool, ImmutableMap.of("commit", x)))
        except ScriptException as e:
            raise ValueError(str(e))

    def transplant_commits_into_branch(self, branch_name: str, hash: str, message: str, transplant: 'Transplant') -> None:
        try:
            transplants = list(transplant.get_hashes_to_transplant().stream().map(Hash.of))
            self.get_store().transplant(BranchName.of(branch_name), Hash.of(hash), transplants)
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(str(e))

    def merge_ref_into_branch(self, branch_name: str, hash: str, merge: 'Merge') -> None:
        try:
            self.get_store().merge(Hash.of(merge.from_ref_name()), BranchName.of(branch_name), Hash.of(hash))
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(str(e))

    def get_entries(self, named_ref: str, params: 'EntriesParams') -> 'ImmutableLogResponse':
        ref_with_hash = self.named_ref_with_hash_or_throw(named_ref, params.hash_on_ref())
        try:
            with self.get_store().get_keys(ref_with_hash) as entry_stream:
                stream = StreamSupport.stream(entry_stream.map(lambda x: EntriesResponse.Entry(builder=lambda: EntriesResponse.Entry(name=from_key(x).name, type=x.type))), False)
                if params.namespace_depth() is not None and params.namespace_depth() > 0:
                    stream = stream.filter(lambda x: len(from_key(x).get_elements()) >= params.namespace_depth()).map(self.truncate).distinct()
                return ImmutableLogResponse(builder=lambda: ImmutableLogResponse().addAll_entries(list(stream.collect(Collectors.toList())))).build()
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(str(e))

    def truncate(self, entry: 'EntriesResponse.Entry', depth: int) -> 'EntriesResponse.Entry':
        if not depth or depth < 1:
            return entry
        type = from_key(entry.name).get_elements().size() > depth and isinstance(from_key(entry.name), Type.UNKNOWN)
        key = ContentsKey.of(from_key(entry.name).get_elements()[:depth])
        return EntriesResponse.Entry(builder=lambda: EntriesResponse.Entry(name=key, type=type))

    def do_ops(self, branch_name: str, hash: str, commit_meta: 'CommitMeta', operations: List['Operation[Contents]']) -> Hash:
        try:
            return self.get_store().commit(BranchName.of(branch_name), Hash.of(hash), meta(self.principal(), commit_meta), operations)
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(str(e))

    def delete_reference(self, ref: 'NamedRef', hash: str) -> None:
        try:
            self.get_store().delete(ref, Hash.of(hash))
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(str(e))

    def assign_reference(self, ref: 'NamedRef', old_hash: str, reference: 'Reference') -> None:
        try:
            resolved = self.get_store().to_ref(ref.name)
            if isinstance(resolved.value, NamedRef):
                self.get_store().assign((resolved.value), Hash.of(old_hash), to_hash(reference.name, reference.hash))
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(str(e))

    @staticmethod
    def from_key(key: 'Key') -> ContentsKey:
        return ContentsKey.of(key.get_elements())

    @staticmethod
    def named_ref_with_hash_or_throw(named_ref: str, hash_on_reference: str) -> WithHash['NamedRef']:
        if not hash_on_reference:
            with self.get_store().get_named_refs() as stream:
                return next(stream)
        else:
            try:
                return Hash.of(hash_on_reference).map(lambda x: NamedRef(x))
            except ReferenceNotFoundException as e:
                raise NessieReferenceNotFoundException(str(e))

    @staticmethod
    def meta(principal: 'Principal', commit_meta: 'CommitMeta') -> CommitMeta:
        if not commit_meta.committer:
            return commit_meta.to_builder().committer(principal.name).build()
        else:
            return commit_meta

    @staticmethod
    def to_hash(reference_name: str, hash_on_reference: bool) -> Hash:
        if not hash_on_reference:
            with self.get_store().to_ref(reference_name) as ref_with_hash:
                return ref_with_hash.hash
        else:
            try:
                return Hash.of(hash_on_reference)
            except ReferenceNotFoundException as e:
                raise ValueError("Required hash is missing")
