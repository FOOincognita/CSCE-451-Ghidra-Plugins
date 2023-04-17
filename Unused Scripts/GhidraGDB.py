from ghidra.app.script import GhidraScript
from ghidra.program.model.mem import MemoryAccessException
from javax.swing import JFrame, JTextArea, JTextField, JScrollPane, JPanel
from java.awt import BorderLayout

import shlex
from subprocess import Popen, PIPE, STDOUT

commands = askString("OS Command", "Enter command", "")
args = shlex.split(commands)
p = Popen(args, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
output = p.stdout.read()
print (output)

class GhidraGdbGef(GhidraScript):

    def __init__(self):
        super(GhidraGdbGef, self).__init__()

    # creates the UI that pops up
    def create_ui(self):
        frame = JFrame("Ghidra GDB/GEF Plugin")
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        frame.setSize(600, 400) # size of UI
        
        panel = JPanel()
        panel.setLayout(BorderLayout())
        frame.add(panel)
        
        output_text_area = JTextArea(10, 30)
        output_text_area.setEditable(False)
        panel.add(JScrollPane(output_text_area), BorderLayout.CENTER)
        
        input_text_field = JTextField()
        input_text_field.addActionListener(
                        self.process_input_factory(input_text_field, output_text_area, frame))
        panel.add(input_text_field, BorderLayout.SOUTH)

        frame.setVisible(True) # IMPORTANT, don't remove
        
    def process_input_factory(self, input_text_field, output_text_area, frame): # process input
        def process_input(event):
            command = input_text_field.getText().strip().lower()
            input_text_field.setText("")
            if command == "exit" or command == "quit":
                frame.dispose()
            elif command == "registers":
                self.print_registers(output_text_area)
            elif command.startswith("registers ["):
                reg_list = [x.upper() for x in command[10:-1]]
                self.print_registers_specific(output_text_area, reg_list)
            elif command == "run" or command == "r": # This is for running the program
                self.run_program()
            elif command.startswith("breakpoint set") or command.startswith("b s"):
                # TODO implement breakpoint set
                output_text_area.append("breakpoint remove function has not been completed")
            elif command.startswith("breakpoint remove") or command.startswith("b r"):
                # TODO implement breakpoint remove
                output_text_area.append("breakpoint set function has not been completed")
            # any new commands go here
            else:
                output_text_area.append(
                    "Unknown command. Available commands: registers, exit.\n") # add any WORKING commands to this list
        return process_input
    
    def print_registers(self, output_text_area):
        registers = currentProgram.getLanguage().getRegisters()
        context = currentProgram.getProgramContext()
        for register in registers:
            if register.isBaseRegister():
                value = context.getRegisterValue(register, register.getAddress())
                output_text_area.append("%s: %s\n" % (register, value))

    def print_registers_specific(self, output_text_area, reg_list): # This doesn't work yet, I'm working on it now
        registers = currentProgram.getLanguage().getRegisters()
        context = currentProgram.getProgramContext()
        for register in registers:
            if register.isBaseRegister() and (register.getName() in reg_list):
                value = context.getRegisterValue(register, register.getAddress())
                output_text_area.append("%s: %s\n" % (register, value))


    def run_program():
        # TODO shell implementation

        # To add things to the output box, use output_text_area.append(what you want to print goes here)
        return 0 # just have this here so it doesn't throw an error and you can run this normally, you can remove once you have anything in this function

    # NOTE: These don't work, edit if you want to try to fix, obviously can only be implemented if we can get the run to work

    # def set_breakpoint(self, address):
    #     symbol_table = program.getSymbolTable()
    #     if not SymbolUtilities.isLabelOrFunctionSymbol(symbol_table.getPrimarySymbol(address)):
    #         symbol_table.createLabel(address, "Breakpoint", program.getDefaultNamespace(), None)     
    
    # def remove_breakpoint(self, address):
    #     symbol_table = program.getSymbolTable()
    #     symbol = symbol_table.getPrimarySymbol(address)
    #     if SymbolUtilities.isLabelOrFunctionSymbol(symbol) and symbol.getName() == "Breakpoint":
    #         symbol.delete()
           
    # Add any new functions here, before run
           
    def run(self):
        self.create_ui()


if __name__ == '__main__':
    script = GhidraGdbGef()
    script.run()
       
