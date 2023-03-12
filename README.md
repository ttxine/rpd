# RPD
**RPD** is an utility to recover 32 and 64 bit ELF executables from a process
dump.

### It supports:
- Statically linked executables without `glibc`
- Dynamically linked executables
- PIE executables

This project based on [ilo pd](http://phrack.org/issues/63/12.html) and
[skpd](https://github.com/whatsbcn/skpd/tree/master).

## Build
To build `rpd` just use:
```bash
make
```

## Example
1) Run the `telnet` program:
    ```bash
    $ telnet
    telnet>
    ```
2) Get the pid with the `ps` utility:
    ```bash
    $ ps -a | grep telnet
      13139 pts/2    00:00:00 telnet
    ```
3) Then use `rpd` to dump the process memory and recover an ELF from it:
    ```bash
    $ ./rpd -p 13139 -o dump
    ```
    Root privileges may be required to run the `rpd` program.
4) Run the recovered executable:
    ```bash
    $ ./dump
    dump>
    ```

## Details
Executable reconstruction from process dump consists of the following steps:

### Get binary information
We want to obtain the information about segments, so the reconstruction
starts with locating program headers. `/proc/[pid]/auxv` contains the 
necessary data: address, entity count, entity size.

### Dump process memory
Once the program headers are located, we can use `ptrace` to read them. Each
program header contains a segment type and a virtual address, so we can 
easily dump LOAD segments. Keep in mind, that if the executable is PIE, then 
the virtual address will be relative and we will need to get the base 
address of the executable.

### Rebuild binary
The ELF header is still the original, but we don't have any section 
information, so we need to reset the section header data.

If the executable contains a DYNAMIC segment, then we can get information 
about the relocations and undo them. Also we can get the GOT offset from it 
and find the PLT for the GOT reconstruction.

### Create executable
Finally, we simply write all the data to a file and make it executable.

## Limitations
- Static binaries using libc always fall with a segmentation fault
- The data segment can contain runtime values, so recovered segment may
differ from the original
- The current version of RPD can't undo direct relocations with implicit
addend
- The current version of RPD can't recover section headers
