package ghidranes.mappers;

import java.util.Arrays;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;
import ghidranes.util.MemoryBlockDescription;

/**
 * https://www.nesdev.org/wiki/UxROM
 * most important bit:
 *  CPU $8000-$BFFF: 16 KB switchable PRG ROM bank
 *  CPU $C000-$FFFF: 16 KB PRG ROM bank, fixed to the last bank
 *
 * This corresponds to iNES Mapper 002, and 094
 * Mapper 180 is very similar, but flips where the fixed/switchable
 * banks are located.
 */
public class UxROMMapper extends NesMapper {
    @Override
    public void updateMemoryMapForRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {

        /* UxROM has switchable 16k PRG ROM banks mapped at 8000-FFFF.
           The lower bank (8000-BFFF) is switchable.
           The upper bank (C000-FFFF) is fixed to the last bank.
        */
        int bankCount = rom.prgRom.length / 0x4000;

        // Load the switchable lower banks
        for (int bank=0; bank<bankCount-1; bank++) {
            int lowerBankPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;
            byte[] lowerBankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x4000, (bank+1)*0x4000);
            MemoryBlockDescription.initialized(0x8000, 0x4000, "PRG Lower "+bank, lowerBankPermissions, lowerBankBytes, bank > 0, monitor)
                .create(program);
        }

        // Load the fixed upper bank (last 16KB)
        int upperBankPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;
        byte[] upperBankBytes = Arrays.copyOfRange(rom.prgRom, (bankCount-1)*0x4000, bankCount*0x4000);
        MemoryBlockDescription.initialized(0xC000, 0x4000, "PRG Upper", upperBankPermissions, upperBankBytes, false, monitor)
            .create(program);
    }
}
