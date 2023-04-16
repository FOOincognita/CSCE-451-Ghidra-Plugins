//@category CSCE451

import generic.stl.Pair;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ghidra script that takes the current function that is tabbed into and replaces the selected options with more legible equivalents, then saves the result to the chosen file.
 */
public class BetterIOExporter extends GhidraScript {

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
        File saveTo = askFile("Select a file to save to", "Ok");
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
        String start = formatted.substring(0, formatted.indexOf('{')+1);
        formatted = formatted.substring(formatted.indexOf('{')+1);
        formatted = formatted.substring(0, formatted.lastIndexOf('}'));
        String[] lines = formatted.split(";");
//        println(Arrays.toString(lines));
        ArrayList<Pair<String, Integer>> couts = new ArrayList<>();
        ArrayList<Pair<String, Integer>> cins = new ArrayList<>();
        StringBuilder cinLine = new StringBuilder("cin >> ");
        StringBuilder multiline = new StringBuilder("cout << ");
//        println(res.getCCodeMarkup().toString());
//        String formattedPretty = res.getCCodeMarkup().toString().substring(res.getCCodeMarkup().toString().indexOf('{')+1);
//        formattedPretty = formattedPretty.substring(0, formattedPretty.lastIndexOf('}'));
//        String[] formattedLines = formattedPretty.split(";");
        int parts = 0;

        int cinParts = 0;

        ArrayList<String> newLines = new ArrayList<>();
        for (String line : lines) {
//            println(line);
            if (formatCin && line.contains("basic_istream") && !(line.indexOf("basic_istream_char_std__char_traits_char__ *") > 0 && line.indexOf("basic_istream_char_std__char_traits_char__ *") < 3)) {
//                println(String.valueOf(line.matches("basic_istream_char_std__char_traits_char__ \\*.*")));
//                println(line);
//                println("saved line: " + line.substring(line.lastIndexOf(",&") + 2, line.length()-1));
//                println("cin detected");
                cinParts++;
                if (line.lastIndexOf(",&") > line.lastIndexOf(",(basic_string *)"))
                    cinLine.append(line, line.lastIndexOf(",&")+2, line.length()-1);
                else
                    cinLine.append(line, line.lastIndexOf(",(basic_string *)")+17, line.length()-1);
                if (line.contains("=")) {
                    cinLine.append(" >> ");
                } else {
                    cinLine.append(";");
                    newLines.add(cinLine.toString());
                    cinLine = new StringBuilder("cin >> ");
                    cinParts = 0;
                }
            } else if (formatCout && line.matches("^\\s*pbVar\\d =.*")) {
//                println(line);
//                println("pbvar match");
                lastArgument(multiline, line);
                multiline.append(" << ");
                parts++;
            } else if (formatCout && line.matches("^\\s*std::((operator__)|(operator<<)).*") || line.contains("std::basic_ostream")) {
//                println(line);
//                println("ending cout match");
//                if (line.matches(".*endl(?!.*\").*")){
                if (line.contains("endl") && !line.contains("\"")) {
                    multiline.append("endl;");
                } else {
                    lastArgument(multiline, line);
                    multiline.append(";");
                }
                parts++;
//                Pair<String, Integer> pair = new Pair<>(multiline.toString(), parts);
                newLines.add(multiline.toString());
                parts = 0;
//                couts.add(pair);
                multiline = new StringBuilder("cout << ");

            } else {
                line = line.replaceAll("basic_string_char_std__char_traits_char__std__allocator_char__", "basic_string<char,std::char_traits<char>,std::allocator<char>>");
                line = line.replaceAll("basic_ostream_char_std__char_traits_char__", "basic_ostream<char,std::char_traits<char>>");
                line = line.replaceAll("basic_istream_char_std__char_traits_char__", "basic_istream<char,std::char_traits<char>>");
                line = line.replaceAll("std::basic_istream<char,std::char_traits<char>>::operator__", "std::basic_istream<char,std::char_traits<char>>::operator>>");
                line = line.replaceAll("basic_string_std__allocator_char__", "basic_string<std::allocator<char>");
                line = line.replaceAll("std::allocator<char>::_allocator", "std::allocator<char>::~allocator");
                line = line.replaceAll("std::operator__\\(\\(basic_istream", "std::operator>>((basic_istream");
                line = line.replaceAll(" = std::operator__", " = std::operator<<");
                line = line.replaceAll("std::operator__\\(\\(basic_ostream", "std::operator<<((basic_ostream");
//                line = line.replaceAll();
                if(line.length() > 3)
                    newLines.add(line + ";");
            }
        }
        try (FileWriter writer = new FileWriter(saveTo)) {
            writer.append(start).append('\n');
            for (String line : newLines) {
                writer.append(line).append('\n');

            }
            writer.append('}');
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
