ghidra-qira-traceloader
=======================

This is a test project to load Qira traces in the Ghidra Debugger.

This repo contains :

  * the Intel Pin tracer of Qira, with slight modifications;
  * the Ghidra Script to import the trace;
  * some example traces (ls and bash).

Import the example traces
-------------------------

  * Import the binary (`elfs/ls` or `elf/bash`, stock binaries from the Ubuntu repos) in Ghidra;
  * Open it with the Debugger;
  * Move the `PopulateTraceQiraCompatible.java` script on your `$HOME/ghidra_scripts/` directory;
  * Run the script, and select the tracefile you want to import (`qira_logs_ls/18612224` or `qira_logs_bash/19333120` respectively);
  * Wait for the import to finish (~1 min for ls, ~10 min for bash);
  * You can now navigate the trace.

Creating your own traces
------------------------

You have to build the Pin tracer.

```
cd tracers
./pin_build.sh
cd pin
./pin-latest/pin -t obj-intel64/qirapin.so -standalone -- /your/binary --your-binary-args
```

You can now import your binary in Ghidra. The trace should be in `/tmp/qira_logs/`.

Current limitations
-------------------

For now, you can only import a single thread.
Importing several threads should not be hard, but is not yet implemented.
Importing several processes is a different problem. Qira seems to handle fine several processes in the same trace, but Ghidra maps the regions for the whole trace.
So a Qira trace containing several processes should be split in several trace in Ghidra.

For now, only the ELFs memory is visible, the heap/stack regions are not created.
For this, we would need to get the start/end address of each one. There are several ways to do this:
  * by looking at the pages that are read/written in the trace (what Qira does);
  * by parsing the `/proc/pid/maps` file (althought the heap/stack size might change);
  * by catching calls to `brk` or watching the lowest `rsp` value, which is probably a bad idea.

Memory regions are loaded with bad permissions. The qira tracers do not give the permissions of the regions mapped into memory. 
The best thing to do is probably to load the ELF ourself into the trace based on the load address. This way, we know if the sections are rwx.

Some things are probably written twice. The tracer saves all changes made to a register.
So if the register is written several times in a tick (eg: on a library function), it will register that.
We should parse it only once, and keep the last one.

Oops, apparently my RIP is off-by-one. Changes happen before the instruction is executed. I should probably fix this :).

Import stats
------------

Importing the `ls` trace

```
Import stats:
 * Instructions:    17452
 * Register Writes: 10812
 * Memory Writes:   61258
 * Ignored:         21820
 * Time elapsed:    PT37.462599S
```

Importing the `bash` trace

```
Import stats:
 * Instructions:    249913
 * Register Writes: 139730
 * Memory Writes:   152906
 * Ignored:         321963
 * Time elapsed:    PT7M58.003359S
```

