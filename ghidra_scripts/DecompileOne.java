// Decompile a single function by virtual address, write the C source to a file.
// Invoked headlessly via:
//   analyzeHeadless ... -process <program> -noanalysis \
//       -scriptPath <ghidra_scripts_dir> \
//       -postScript DecompileOne.java 0xVVVVVVVV /path/to/output.c
//
// @category iVCS

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.FileWriter;
import java.io.IOException;

public class DecompileOne extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new RuntimeException(
                "expected 2 args (va_hex, out_path); got " + args.length);
        }
        String vaHex = args[0];
        String outPath = args[1];

        long va = vaHex.toLowerCase().startsWith("0x")
            ? Long.parseLong(vaHex.substring(2), 16)
            : Long.parseLong(vaHex);

        Address addr = currentProgram.getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(va);
        Function func = getFunctionContaining(addr);
        if (func == null) {
            // Ghidra's auto-analysis misses functions reached only by indirect
            // calls, and small thunks/stubs (the project's function list, by
            // contrast, is authoritative). Materialize one at the asserted
            // entry: disassemble, then define the function so it can decompile.
            disassemble(addr);
            func = createFunction(addr, null);
            if (func == null) {
                throw new RuntimeException(String.format(
                    "no function at 0x%08x, and one could not be created "
                        + "(address may not be valid code)",
                    va));
            }
        }

        DecompInterface iface = new DecompInterface();
        String cSource;
        try {
            if (!iface.openProgram(currentProgram)) {
                throw new RuntimeException(
                    "DecompInterface.openProgram failed: " + iface.getLastMessage());
            }
            DecompileResults res = iface.decompileFunction(func, 60, monitor);
            if (!res.decompileCompleted()) {
                throw new RuntimeException(String.format(
                    "decompile failed at 0x%08x: %s",
                    va, res.getErrorMessage() != null ? res.getErrorMessage() : ""));
            }
            cSource = res.getDecompiledFunction().getC();
        } finally {
            iface.dispose();
        }

        try (FileWriter w = new FileWriter(outPath)) {
            w.write(cSource);
        }
    }
}
