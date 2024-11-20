import ghidra.app.script.GhidraScript
from ghidra.program.model.address import AddressSetView
from ghidra.program.model.listing import InstructionIterator
from ghidra.program.model.pcode import PcodeOp, BookmarkType

class MarkCallOtherPcode(GhidraScript):
    def run(self):
        if self.currentProgram is None:
            return
        
        set = self.currentSelection
        if set is None or len(set) == 0:
            set = self.currentProgram.getMemory().getExecuteSet()
        
        Disassembler.clearUnimplementedPcodeWarnings(self.currentProgram, set, self.monitor)
        
        completed = 0
        self.monitor.initialize(len(set))
        
        instructions = self.currentProgram.getListing().getInstructions(set, True)
        while instructions.hasNext():
            self.monitor.checkCanceled()
            instr = instructions.next()

            pcode_ops = instr.getPcode()
            
            for op in pcode_ops:
                if op.getOpcode() == PcodeOp.CALLOTHER:
                    self.markCallOtherPcode(instr, op)

            completed += len(set)
            if (completed % 1000) == 0:
                self.monitor.setProgress(completed)

    def markCallOtherPcode(self, instr, op):
        self.currentProgram.getBookmarkManager().setBookmark(instr.getAddress(), BookmarkType.WARNING,
                                                              "CallOther PcodeOp",
                                                              self.currentProgram.getLanguage().getUserDefinedOpName(op.getInput(0).getOffset()))
