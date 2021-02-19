/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import com.google.common.collect.Range;

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.database.UndoableTransaction;

/**
 * This script populates a trace database for demonstrations purposes and opens it in the current
 * tool.
 * 
 * <p>
 * Your current tool had better be the "TraceBrowser"! The demonstration serves two purposes. 1) It
 * puts interesting data into the TraceBrowser and leaves some annotations as an exercise. 2) It
 * demonstrates how a decent portion the Trace API works.
 * 
 * <p>
 * A Trace is basically a collection of observations of memory and registers over the lifetime of an
 * application or computer system. In Ghidra, the Trace object also supports many of the same
 * annotations as does Program. In the same way that Program brings knowledge markup to an image of
 * bytes, Trace brings knowledge markup to bytes observed over time.
 * 
 * <p>
 * Effectively, if you take the cross-product of Program with time and add Threads, Breakpoints,
 * etc., you get Trace. It's a lot. In order to use all the UI components which take a Program,
 * Trace can present itself as a Program at a particular point in time.
 * 
 * <p>
 * Each particular component will be introduced as its used in the script below, but for now some
 * core concepts:
 * 
 * <ul>
 * <li>A point in time is called a "tick." These don't necessarily correspond to any real unit of
 * time, though they may. The only requirement is that they are numbered in chronological
 * order.</li>
 * <li>Every annotation has a "lifespan," which is the range of ticks for which the annotation is
 * effective. Some annotations may overlap, others may not. In general, if the corresponding concept
 * in Program permits address overlap, then Trace permits both address and time overlap. If not,
 * then neither is permitted. In essense, Trace defines overlap as the intersection of rectangles,
 * where an annotation's X dimension is it's address range, and its Y dimension is its lifespan.
 * </li>
 * <li>Observations in memory happen at a particular tick and are assumed in effect until another
 * observation changes that. To record the "freshness" of observations, the memory manager tags
 * regions as KNOWN, UNKNOWN, or ERROR. An observation implicitly marks the affected region as
 * KNOWN. The intent is to grey the background for regions where memory is UNKNOWN for the current
 * tick.</li>
 * <li>Observations of registers behave exactly the same as observations for memory, by leveraging
 * Ghidra's "register space." The only difference is that those observations must be recorded with
 * respect to a given thread. Each thread is effectively allocated its own copy of the register
 * space. Most the the API components require you to obtain a special "register space" for a given
 * thread before recording observations of or applying annotations to that thread.</li>
 * </ul>
 * 
 * <p>
 * After you've run this script, a trace should appear in the UI. Note that there is not yet a way
 * to save a trace in the UI. As an exercise, try adding data units to analyze the threads' stacks.
 * It may take some getting accustomed to, but the rules for laying down units should be very
 * similar to those in a Program. However, the Trace must take the applied units and decide how far
 * into the future they are effective. In general, it defaults to "from here on out." However, two
 * conditions may cause the trace to choose an ending tick: 1) The underlying bytes change sometime
 * in the future, and 2) There is an overlapping code unit sometime in the future.
 * 
 * <p>
 * The trace chooses the latest tick possible preceding any byte change or existing code unit, so
 * that the unit's underlying bytes remain constant for its lifespan, and the unit does not overlap
 * any existing unit. This rule causes some odd behavior for null-terminated strings. I intend to
 * adjust this rule slightly for static data types wrt/ byte changes. For those, the placed unit
 * should be truncated as described above, however, another data unit of the same type can be placed
 * at the change. The same rule is then applied iteratively into the future until an overlapping
 * unit is encountered, or there are no remaining byte changes.
 */
public class PopulateTraceQiraCompatible extends GhidraScript {
    private Language lang;
    private CompilerSpec cspec;
    private Trace trace;
    private TraceMemoryManager memory;
    private TraceModuleManager modules;
    private TraceThreadManager threads;
    private TraceTimeManager timeManager;

    private AddressSpace defaultSpace;

    private DebuggerTraceManagerService manager;
    
    private String tracePath;

    /**
     * Maps an (ELF Path, offset) pair to the file containing the region bytes.
     */
    Map<Pair<String, Long>, File> imagesMap;
    
    private static final Map<Long, String> register_map = createRegisterMap();
    
    /**
     * Create the mapping between Qira register address and X86 register name
     * 
     * @return the mapping
     */
    protected static Map<Long, String> createRegisterMap() {
        Map <Long, String> result = new HashMap<Long, String>();
        result.put(0x00L, "RAX");
        result.put(0x08L, "RCX");
        result.put(0x10L, "RDX");
        result.put(0x18L, "RBX");
        result.put(0x20L, "RSP");
        result.put(0x28L, "RBP");
        result.put(0x30L, "RSI");
        result.put(0x38L, "RDI");
        result.put(0x40L, "R8");
        result.put(0x48L, "R9");
        result.put(0x50L, "R10");
        result.put(0x58L, "R11");
        result.put(0x60L, "R12");
        result.put(0x68L, "R13");
        result.put(0x70L, "R14");
        result.put(0x78L, "R15");
        result.put(0x80l, "RIP");
        return result;
    }
    
    final int IS_VALID   = 0x80000000;
    final int IS_WRITE   = 0x40000000;
    final int IS_MEM     = 0x20000000;
    final int IS_START   = 0x10000000;
    final int IS_SYSCALL = 0x08000000;
    final int SIZE_MASK  = 0xFF;

    /**
     * Create an address in the processor's (x86_64) default space.
     * 
     * @param offset the byte offset
     * @return the address
     */
    protected Address addr(long offset) {
        return defaultSpace.getAddress(offset);
    }

    /**
     * Create an address range in the processor's default space.
     * 
     * @param min the minimum byte offset
     * @param max the maximum (inclusive) byte offset
     * @return the range
     */
    protected AddressRange rng(long min, long max) {
        return new AddressRangeImpl(addr(min), addr(max));
    }

    /**
     * Get a register by name
     * 
     * @param name the name
     * @return the register
     */
    protected Register reg(String name) {
        return lang.getRegister(name);
    }
    
    /**
     * Parses the "_images" directory.
     * 
     * For -standalone traces, we explore the files in _images and create a Map<Pair<Filename, Offset>, File>
     * @throws UnsupportedEncodingException
     */
    protected void parseImages() throws UnsupportedEncodingException {
        imagesMap = new HashMap<>();
        
        File imagesDir = new File(tracePath + "_images");
        for(File imageFile : imagesDir.listFiles()) {
            String path = URLDecoder.decode(imageFile.getName(), "utf-8");
            
            if(imageFile.isDirectory()) {
                // The regions are split in the traces, create an entry for each one
                for(File regionFile : imageFile.listFiles()) {
                    long offset = Long.parseUnsignedLong(regionFile.getName(), 16);
                    imagesMap.put(new Pair<>(path, offset), regionFile);
                }
            } else {
                // The whole image is contained in a single file
                imagesMap.put(new Pair<>(path, 0L), imageFile);
            }
        }
    }
    
    /**
     * Parses the "_base" file
     * 
     * The file lists the different ELFs that are loaded in memory, similar to /proc/<pid>/maps.
     * For each file, we create a Module. For each loaded program segment, we create a Region and fill it with the content from _images.
     * 
     * @throws Exception
     */
    protected void parseBase() throws Exception {
        Map<String, Long> minAddrMap = new HashMap<>();
        Map<String, Long> maxAddrMap = new HashMap<>();
        
        BufferedReader reader = new BufferedReader(new FileReader(tracePath + "_base"));
        String line;
        while((line = reader.readLine()) != null) {
            // Line parsing
            String[] tokens = line.split(" ");

            String[] range = tokens[0].split("-");
            long begin = Long.parseUnsignedLong(range[0], 16);
            long end = Long.parseUnsignedLong(range[1], 16);
            long offset = Long.parseUnsignedLong(tokens[1], 16);
            String filename = tokens[2];
            
            File f = imagesMap.get(new Pair<>(filename, offset));
            
            // Create a region
            String regionName = filename + "(" + Long.toUnsignedString(offset, 16) + ")";
            AddressRange rng = rng(begin, end - 1);
            memory.addRegion(regionName, Range.atLeast(0L), rng, TraceMemoryFlag.READ, TraceMemoryFlag.WRITE, TraceMemoryFlag.EXECUTE);
            
            // Fill the initial bytes
            ByteProvider provider = new RandomAccessByteProvider(f);
            byte[] bytes = provider.readBytes(0, f.length());
            ByteBuffer buf = ByteBuffer.allocate((int) f.length());
            buf.put(bytes);
            memory.putBytes(0, rng.getMinAddress(), buf.flip());
            provider.close();
            
            // Compute the min/max of vaddr for every file
            if(Long.compareUnsigned(begin, minAddrMap.getOrDefault(filename, -1L)) < 0) {
                minAddrMap.put(filename, begin);
            }
            if(Long.compareUnsigned(end, maxAddrMap.getOrDefault(filename, 0L)) > 0) {
                maxAddrMap.put(filename, end);
            }
        }
        
        for(String filename : minAddrMap.keySet()) {
            long minAddr = minAddrMap.get(filename);
            long maxAddr = minAddrMap.get(filename);
            AddressRange rng = rng(minAddr, maxAddr - 1);
            modules.addLoadedModule(filename, filename, rng, 0);
        }
        
        reader.close();
    }
    
    /**
     * Parses the "_strace" file
     * 
     * For now, we only create a snapshot in the timeline.
     * 
     * @throws Exception
     */
    protected void parseStrace() throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(tracePath + "_strace"));
        String line;
        while((line = reader.readLine()) != null) {
            String[] tokens = line.split(" ", 3);
            int tick = Integer.parseInt(tokens[0]);
            //int tid = Integer.parseInt(tokens[1]);
            //String syscall = tokens[2];
            timeManager.getSnapshot(tick, true);
        }
        reader.close();
    }
    
    @Override
    protected void run() throws Exception {
        /*
         * As mentionned in issue #2398, the ask* function close the TaskMonitor.
         * If you want to check the progress, replace this line with a hardcoded path. 
         */
        tracePath = askFile("Select a Qira trace file", "Load").getAbsolutePath();
        
        cspec = currentProgram.getCompilerSpec();
        lang = currentProgram.getLanguage();
        defaultSpace = lang.getAddressFactory().getDefaultAddressSpace();

        trace = new DBTrace("mytrace", cspec, this);
        memory = trace.getMemoryManager();
        modules = trace.getModuleManager();
        threads = trace.getThreadManager();
        timeManager = trace.getTimeManager();
        manager = state.getTool().getService(DebuggerTraceManagerService.class);

        try (UndoableTransaction tid =
                UndoableTransaction.start(trace, "Populating modules / regions", true)) {
            
            monitor.setMessage("Loading progam and libraries in memory");
            parseImages();
            parseBase();
            
            monitor.setMessage("Loading register/memory writes");
            parseTrace();
        }
        
        manager.openTrace(trace);
        manager.activateTrace(trace);

        return;
    
    }
    
    /**
     * Parses the trace file containing the register/memory writes.
     * 
     * @throws Exception
     */
    protected void parseTrace() throws Exception {
        RandomAccessFile aFile = new RandomAccessFile(tracePath, "r");
        
        FileChannel inChannel = aFile.getChannel();
        ByteBuffer buffer = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buffer.clear();
        
        // Read logstate
        inChannel.read(buffer);
        buffer.flip();
        int change_count = buffer.getInt();
        long last_tick = buffer.getInt();
        buffer.getInt(); // is_filtered
        long first_tick = buffer.getInt();
        buffer.getInt(); // ppid
        buffer.getInt(); // pid
        buffer.clear();
        
        // Create thread
        TraceThread th = threads.addThread("t0", Range.closed(first_tick, last_tick));
        TraceMemoryRegisterSpace regspace = memory.getMemoryRegisterSpace(th, true);
        
        if(true) {

            int nInstructions = 0;
            int nMemoryWrites = 0;
            int nRegisterWrites = 0;
            int nIgnored = 0;
            Instant startTime = Instant.now();

            Register rip = reg("RIP");
    
            monitor.initialize(change_count);
            
            while(!(monitor.isCancelled()) && (inChannel.read(buffer) == 24)) {
                // Read change
                buffer.flip();
                long addr = buffer.getLong();
                long data = buffer.getLong();
                int tick = buffer.getInt();
                int flags = buffer.getInt();
                
                // We assume that invalid records marks the end
                if((flags & IS_VALID) == 0)
                    break;
                
                if((flags & IS_START) == IS_START) {
                    // Instruction executed
                    RegisterValue ripValue = new RegisterValue(rip, BigInteger.valueOf(addr));
                    regspace.setValue(tick, ripValue);
                    nInstructions++;
                } else if((flags & IS_WRITE) == IS_WRITE) {
                    if((flags & IS_MEM) == IS_MEM) {
                        // Memory write
                        int size = (flags & SIZE_MASK) / 8;
                        buffer.position(8).limit(8 + size);
                        memory.putBytes(tick, addr(addr), buffer);
                        nMemoryWrites++;
                    } else {
                        // Register write
                        String regName = register_map.get(addr);
                        Register reg = reg(regName);
                        RegisterValue regValue = new RegisterValue(reg, BigInteger.valueOf(data));
                        regspace.setValue(tick, regValue);
                        nRegisterWrites++;
                    }
                } else {
                    nIgnored++;
                }
                buffer.clear();
                monitor.incrementProgress(1);
            }
            
            Instant endTime = Instant.now();
            Duration timeElapsed = Duration.between(startTime, endTime);
            println("Import stats:");
            println(" * Instructions:    " + nInstructions);
            println(" * Register Writes: " + nRegisterWrites);
            println(" * Memory Writes:   " + nMemoryWrites);
            println(" * Ignored:         " + nIgnored);
            println(" * Time elapsed:    " + timeElapsed.toString());
        }
        
        inChannel.close();
        aFile.close();
    }
}
