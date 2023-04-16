//@category CSCE451

import generic.stl.Pair;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ghidra script that takes the current function that is tabbed into and for every selected pattern, will add comments surrounding the blocks of code with a more legible format.
 */
public class BetterIOReadability extends GhidraScript {

    public void run() throws Exception {
        JCheckBox coutBox = new JCheckBox("cout");
        JCheckBox cinBox = new JCheckBox("cin");
        Object[] params = {coutBox, cinBox};
        int result = JOptionPane.showConfirmDialog(null, params, "Select IO Improvement Options", JOptionPane.DEFAULT_OPTION);
        boolean formatCin = cinBox.isSelected();
        boolean formatCout = coutBox.isSelected();
        // Get the current function
        Function function = getFunctionContaining(currentAddress);
        if (function == null) {
            println("No function at current address.");
            return;
        }
        AddressSetView preReadAddresses = function.getBody();
        Listing prelisting = currentProgram.getListing();
        CodeUnitIterator preReadIter = prelisting.getCodeUnits(preReadAddresses, true);
        while (preReadIter.hasNext()) {
            CodeUnit codeUnit = preReadIter.next();
            codeUnit.setComment(CodeUnit.PRE_COMMENT, null);
            codeUnit.setComment(CodeUnit.POST_COMMENT, null);
        }
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        DecompileResults res = decomp.decompileFunction(function, 300, TaskMonitor.DUMMY);
        println(res.getDecompiledFunction().getC());
        String formatted = res.getDecompiledFunction().getC();
        formatted = formatted.replaceAll("(?!;)\n\\s+", "");
        formatted = formatted.substring(formatted.indexOf('{')+1);
        formatted = formatted.substring(0, formatted.lastIndexOf('}'));
        String[] lines = formatted.split(";");
//        println(Arrays.toString(lines));
        ArrayList<Pair<String, Integer>> couts = new ArrayList<>();
        ArrayList<Pair<String, Integer>> cins = new ArrayList<>();
        StringBuilder cinLine = new StringBuilder("cin >> ");
        StringBuilder multiline = new StringBuilder("cout << ");
        int parts = 0;

        int cinParts = 0;
        for(String line : lines){
//            println(line);
            if(formatCin && line.contains("basic_istream") && !(line.indexOf("basic_istream_char_std__char_traits_char__ *") > 0 && line.indexOf("basic_istream_char_std__char_traits_char__ *") < 3)){
//                println(String.valueOf(line.matches("basic_istream_char_std__char_traits_char__ \\*.*")));
//                println(line);
//                println("saved line: " + line.substring(line.lastIndexOf(",&") + 2, line.length()-1));
//                println("cin detected");
                cinParts++;
                if (line.lastIndexOf(",&") > line.lastIndexOf(",(basic_string *)"))
                    cinLine.append(line, line.lastIndexOf(",&")+2, line.length()-1);
                else
                    cinLine.append(line, line.lastIndexOf(",(basic_string *)")+17, line.length()-1);
                if (line.contains("=")){
                    cinLine.append(" >> ");
                }
                else{
                    cinLine.append(";");
                    cins.add(new Pair<>(cinLine.toString(), cinParts));
                    cinLine = new StringBuilder("cin >> ");
                    cinParts = 0;
                }
            }
            else if(formatCout && line.matches("^\\s*pbVar\\d =.*")){
//                println(line);
//                println("pbvar match");
                lastArgument(multiline, line);
                multiline.append(" << ");
                parts++;
            }
            else if(formatCout && line.matches("^\\s*std::((operator__)|(operator<<)).*") || line.contains("std::basic_ostream")){
//                println(line);
//                println("ending cout match");
//                if (line.matches(".*endl(?!.*\").*")){
                if (line.contains("endl") && !line.contains("\"")){
                    multiline.append("endl;");
                }
                else {
                    lastArgument(multiline, line);
                    multiline.append(";");
                }
                parts++;
                Pair<String, Integer> pair = new Pair<>(multiline.toString(), parts);
                parts = 0;
                couts.add(pair);
                multiline = new StringBuilder("cout << ");

            }
        }

        // Get the listing and code unit iterator for the function
        Listing listing = currentProgram.getListing();
        AddressSetView functionAddresses = function.getBody();
        CodeUnitIterator codeUnitIter = listing.getCodeUnits(functionAddresses, true);
        int num = 0;
        String str = "";

        int cinNum = 0;
        String cinStr = "";
        // Iterate over each code unit in the function
        println(String.valueOf(couts.size()));
        while (codeUnitIter.hasNext()) {
            CodeUnit codeUnit = codeUnitIter.next();
            if (codeUnit.getMnemonicString().equals("CALL")){
                Function func = currentProgram.getFunctionManager().getFunctionAt(codeUnit.getOperandReferences(0)[0].getToAddress());
                if (formatCout && func.toString().matches("^((<EXTERNAL>::std::operator<<)|(<EXTERNAL>::std::basic_ostream)).*")) {
                    try {
                        println(str);
                        println(String.valueOf(num));
                        if (num-- <= 0) {
                            str = couts.get(0).first;
                            num = couts.get(0).second-1;
                            couts.remove(0);
                            codeUnit.setComment(CodeUnit.PRE_COMMENT, str + "\ncout block begins here");
                        } else if (num == 0) {
                            codeUnit.setComment(CodeUnit.POST_COMMENT, "cout block ends here");
                        }
                    }
                    catch (Exception e){
                        println(String.valueOf(num));
                        throw e;
                    }
//                    println(func.toString());
                }
                else if(formatCin && func.toString().matches("^((<EXTERNAL>::std::operator>>)|(<EXTERNAL>::std::basic_istream)).*")){
                    try {
                        println(cinStr);
                        println(String.valueOf(cinNum));
                        if (cinNum-- <= 0) {
                            cinStr = cins.get(0).first;
                            cinNum = cins.get(0).second-1;
                            cins.remove(0);
                            codeUnit.setComment(CodeUnit.PRE_COMMENT, cinStr + "\ncin block begins here");
                        } else if (num == 0) {
                            codeUnit.setComment(CodeUnit.POST_COMMENT, "cin block ends here");
                        }
                    }
                    catch (Exception e){
                        println(String.valueOf(cinNum));
                        throw e;
                    }
                }

            }
            //        00102308 e8 03 fe        CALL       <EXTERNAL>::std::basic_ostream<char,std::char_   undefined operator<<(basic_ostre
        //                 ff ff

        //        00102308 e8 03 fe        CALL       <EXTERNAL>::std::basic_ostream<char,std::char_   undefined operator<<(basic_ostre
        //[ 0xe8, 0x03, 0xfe, 0xff, 0xff ]
//                codeUnit.setComment(CodeUnit.PRE_COMMENT, codeUnit.toString());

//            codeUnit.setComment(CodeUnit.PRE_COMMENT, codeUnit.getOperandReferences());
        }
    }

    private void lastArgument(StringBuilder multiline, String line) {
        Pattern lastComma = Pattern.compile("(,\".*\"\\))");
        Matcher finder = lastComma.matcher(line);
        int lastIndex = -1;
        while(finder.find(Math.max(lastIndex+1, 0))){
//            println("searching");
            lastIndex = finder.start();
        }
        if (lastIndex == -1){
            lastIndex = line.lastIndexOf(',');
        }
//        println("done");
        multiline.append(line, lastIndex + 1, line.length()-1);
    }
}
