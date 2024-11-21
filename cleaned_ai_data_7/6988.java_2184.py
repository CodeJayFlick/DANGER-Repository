import ghidra.app.script.GhidraScript;
from ghidra.program.model.data import DataType;

class BTreeAnnotationScript(GhidraScript):
    def run(self) -> None:
        address = self.currentProgram.getMinAddress();

        provider = MemoryByteProvider(self.currentProgram.getMemory(), address);

        reader = BinaryReader(provider, False);

        root = BTreeRootNodeDescriptor(reader);

        markupRecordOffsets(self.currentProgram, root, 0, root);

        header_node_data = createBTreeNode(self.currentProgram, root, 0);

        header_record_data = createBTreeHeaderRecord(self.currentProgram, root.getHeaderRecord(), header_node_data.getLength());

        user_data_record_data = createUserDataRecord(self.currentProgram, root.getUserDataRecord(), header_node_data.getLength() + header_record_data.getLength())

        map_record_data = createMapRecord(self.currentProgram, root.getMapRecord(), header_node_data.getLength() + header_record_data.getLength() + user_data_record_data.getLength())

        if map_record_data is None:
            print("mapRecordData == null ?????")

        processNodes(self.currentProgram, root)

    def getScriptAnalysisMode(self) -> AnalysisMode:
        return AnalysisMode.DISABLED

    def process_nodes(self, program: Program, node_descriptor: BTreeNodeDescriptor) -> int:
        node_index = 1;
        min = (int)(program.getMinAddress().getOffset());
        max = (int)(program.getMaxAddress().getOffset());

        monitor.set_maximum(max - min);
        monitor.set_message("Applying node descriptors...");

        node_size = root.getHeaderRecord().getNodeSize() & 0xffff;

        for i in range(node_size, program.getMemory().getSize(), node_size):
            if monitor.is_cancelled():
                break;
            monitor.set_progress(min + i);

            node_i = root.getNode(node_index);
            createBTreeNode(program, node_i, i);

            buffer = StringBuffer();
            buffer.append("Index: 0x" + str(hex(node_index)) + "\n");
            buffer.append("flink: 0x" + str(hex(node_i.getFLink())) + "\n");
            buffer.append("blink: 0x" + str(hex(node_i.getBLink())) + "\n");
            buffer.append("kind: " + node_i.getKind() + "\n");
            buffer.append("Records: 0x" + str(hex(node_i.getNumRecords())) + "\n");

            set_plate_comment(to_addr(i), buffer.toString());

            markup_b_tree_node_data(program, node_i);

            markup_record_offsets(program, root, i, node_i);

            node_index += 1;

        return node_index

    def markup_record_offsets(self, program: Program, root: BTreeRootNodeDescriptor, offset: int, node_descriptor: BTreeNodeDescriptor) -> None:
        # TODO
        pass

    def markup_b_tree_node_data(self, program: Program, descriptor: BTreeNodeDescriptor) -> None:
        for record in descriptor.getRecords():
            address = to_addr(record.getRecordOffset());
            data_type = record.to_data_type();
            data = create_data(address, data_type);
            fragment = create_fragment(data_type.name(), data.getMinAddress(), data.getLength());
            set_plate_comment(address, str(record.getType()) + " 0x" + str(hex(record.getFileID())));

    def markup_decmpfs(self, program: Program, descriptor: BTreeNodeDescriptor, record: BTreeNodeRecord, address: Address) -> None:
        header = record.getDecmpfsHeader();
        data_type = header.to_data_type();
        data = create_data(address, data_type);
        change_endian_settings(data);

    def create_map_record(self, program: Program, map_record: BTreeMapRecord, offset: int) -> Data:
        address = to_addr(offset);
        data_type = map_record.to_data_type();
        return create_data(address, data_type)

    def create_user_data_record(self, program: Program, user_data_record: BTreeNodeUserDataRecord, offset: int) -> Data:
        address = to_addr(offset);
        data_type = user_data_record.to_data_type();
        return create_data(address, data_type)

    def create_b_tree_header_record(self, program: Program, header_record: BTreeHeaderRecord, offset: int) -> Data:
        address = to_addr(offset);
        data_type = header_record.to_data_type();
        return create_data(address, data_type)

    def create_b_tree_node(self, program: Program, node_descriptor: BTreeNodeDescriptor, offset: int) -> Data:
        address = to_addr(offset);
        data_type = node_descriptor.to_data_type();
        return create_data(address, data_type)

    def change_endian_settings(self, data: Data) -> None:
        for i in range(data.getNumComponents()):
            component = data.getComponent(i)
            settings_definitions = component.getDataType().getSettingsDefinitions()
            for j in range(len(settings_definitions)):
                if isinstance(settings_definitions[j], EndianSettingsDefinition):
                    setting = settings_definitions[j]
                    setting.set_big_endian(component, False)

    def create_data(self, address: Address, data_type: DataType) -> Data:
        pass

    def to_addr(self, offset: int) -> Address:
        return self.currentProgram.getAddress(offset)
