class MDCLIArrayProperty:
    def __init__(self, dmang):
        super().__init__(dmang)

#    public MDCLIArrayProperty(String modifierTypeName, MDMang dmang) throws MDException {
#        super(modifierTypeName, dmang);
#        self.parse(dmang);
#    }

    # @Override
    def parse(self, dmang):
        iter = dmang.get_character_iterator_and_builder()
        ch = iter.next()

        if '0' <= str(ch) <= '9':
            array_rank = int(str(ch))
        elif 'A' <= str(ch) <= 'F':
            array_rank = ord(str(ch)) - ord('A') + 10
        else:
            raise MDException("invalid cli:array rank")

        ch = iter.next()
        if '0' <= str(ch) <= '9':
            array_rank *= 16 + int(str(ch))
        elif 'A' <= str(ch) <= 'F':
            array_rank *= 16 + ord(str(ch)) - ord('A') + 10
        else:
            raise MDException("invalid cli:array rank")

        # TODO: might remove the following line... char might be an ignored cvmod, to be parsed outside of this object
        iter.next()

    def insert(self, builder):
        builder.insert(prefix_emit_clause)
        if array_rank > 1:
            builder.append(intermediate_emit_clause + str(array_rank))
        builder.append(suffix_emit_clause)

#    @Override
    def emit(self, builder):
        builder.insert(0, prefix_emit_clause)
        if array_rank > 1:
            builder.append(intermediate_emit_clause + str(array_rank) + suffix_emit_clause)
        return builder.toString()
