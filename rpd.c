#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

#ifdef __x86_64__
#define ELF_R_TYPE ELF64_R_TYPE
#define R_NONE R_X86_64_NONE
#define R_DIRECT R_X86_64_64
#define R_COPY R_X86_64_COPY
#define R_GLOB_DAT R_X86_64_GLOB_DAT
#define R_RELATIVE R_X86_64_RELATIVE

typedef Elf64_auxv_t Elf_auxv_t;
typedef Elf64_Word Elf_Word;
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Off Elf_Off;
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Rel Elf_Rel;
typedef Elf64_Rela Elf_Rela;
#endif /* __x86_64__ */

#ifdef __i386__
#define ELF_R_TYPE ELF32_R_TYPE
#define R_NONE R_386_NONE
#define R_DIRECT R_386_32
#define R_COPY R_386_COPY
#define R_GLOB_DAT R_386_GLOB_DAT
#define R_RELATIVE R_386_RELATIVE

typedef Elf32_auxv_t Elf_auxv_t;
typedef Elf32_Word Elf_Word;
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Off Elf_Off;
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Rel Elf_Rel;
typedef Elf32_Rela Elf_Rela;
#endif /* __i386__ */

static const char* program_name = NULL;

/* If nonzero, then print messages describing what is being done */
static int verbose = 0;


static void
report_error(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", program_name);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}


static void
report_warning(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: warning: ", program_name);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}


static void
report_info(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: info: ", program_name);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}


/*
 * Fill "phdr_absolute_addr", "phdr_len", "phdr_entity_size" with
 * binary information.
 * Returns 0 on success, -1 on failure. The returned data must be
 * checked for nonzero values.
 */
static int
get_binary_information(pid_t pid, Elf_Addr* phdr_absolute_addr,
                       size_t* phdr_len, size_t* phdr_entity_size)
{
    int ret = -1;

    FILE* auxv = NULL;
    char* auxv_path = NULL;
    size_t auxv_path_size = 0;
    Elf_auxv_t auxv_entry = { 0 };

    /*
     * /proc/[pid]/auxv contains the necessary data: address, entry
     * number and entity size.
     */
    auxv_path_size = snprintf(NULL, 0, "/proc/%d/auxv", pid);
    auxv_path = malloc(auxv_path_size + 1);
    snprintf(auxv_path, auxv_path_size + 1, "/proc/%d/auxv", pid);
    auxv = fopen(auxv_path, "r");
    if (auxv == NULL) {
        report_error("can't open '/proc/%d/auxv': %s", pid, strerror(errno));
        goto cleanup;
    }

    *phdr_absolute_addr = 0;
    *phdr_entity_size = 0;
    *phdr_len = 0;
    while (fread(&auxv_entry, sizeof(Elf_auxv_t), 1, auxv)) {
        switch(auxv_entry.a_type) {
        case AT_PHDR:
            *phdr_absolute_addr = auxv_entry.a_un.a_val;
            break;

        case AT_PHENT:
            *phdr_entity_size = auxv_entry.a_un.a_val;
            break;

        case AT_PHNUM:
            *phdr_len = auxv_entry.a_un.a_val;
            break;

        case AT_NOTELF:
            report_error("program is not ELF");
            goto cleanup;

        default:
            break;
        }
    }

    if (ferror(auxv)) {
        report_error("can't read from '/proc/%d/auxv': %s", pid,
                     strerror(errno));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (auxv != NULL)
        fclose(auxv);

    free(auxv_path);
    return ret;
}


static bool
is_phdr_entity_size_valid(size_t entity_size)
{
    return entity_size == sizeof(Elf_Phdr);
}


static bool
is_rel_entity_size_valid(size_t size, size_t entity_size,
                         bool with_addend)
{
    size_t target_size = with_addend ? sizeof(Elf_Rela) : sizeof(Elf_Rel);
    return entity_size == target_size && size % entity_size == 0;
}


static bool
process_exists(pid_t pid)
{
    errno = 0;
    kill(pid, 0);
    return errno != ESRCH;
}


static int
attach_to_process(pid_t pid)
{
    if ((ptrace(PTRACE_ATTACH, pid, 0, 0)) < 0) {
        report_error("can't attach to process: %s", strerror(errno));
        return -1;
    }

	waitpid(pid, NULL, WUNTRACED);
    return 0;
}


static int
detach_from_process(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
        report_error("can't detach from process: %s", strerror(errno));
        return -1;
    }

    return 0;
}


/*
 * Read "len" bytes at "addr" from process memory and write them into
 * "dest".
 * To read process memory you need to attach to process first. See
 * attach_to_process.
 * Returns 0 on success, -1 on failure.
 */
static int
read_process_memory(pid_t pid, size_t addr, void *dest, size_t len)
{
    size_t nread = 0;
    errno = 0;

    for (size_t i = 0; i < len / sizeof(size_t); i++) {
        size_t word = ptrace(PT_READ_D, pid, addr + i * sizeof(size_t), 0);

        if (word == -1 && errno != 0) {
            report_error("can't read process memory at address 0x%08lx: %s",
                         addr + i * sizeof(size_t), strerror(errno));
            return -1;
        }

        memcpy(dest + i * sizeof(size_t), &word, sizeof(size_t));
        nread += sizeof(size_t);
    }

    if (nread < len) {
        size_t word = ptrace(PT_READ_D, pid, addr + nread, 0);

        if (word == -1 && errno != 0) {
            report_error("can't read process memory at address 0x%08lx: %s",
                         addr + nread, strerror(errno));
            return -1;
        }

        memcpy(dest + nread, &word, len - nread);
    }

    return 0;
}


/*
 * Find ELF header in process memory.
 * To read process memory you need to attach to process first. See
 * attach_to_process.
 * Returns ELF header address on success, 0 on failure.
 */
static Elf_Addr
find_elf_header(pid_t pid, Elf_Addr phdr_absolute_addr)
{
    for (size_t addr = phdr_absolute_addr - SELFMAG; ; addr--) {
        uint8_t buf[SELFMAG] = { 0 };

        if (read_process_memory(pid, addr, &buf, SELFMAG) < 0)
            return 0;

        if (memcmp(&buf, ELFMAG, SELFMAG) == 0)
            return addr;
    }
}


/*
 * Dump the memory image of process "pid".
 * On success set "size" to the dump size, "load_addr" to the base
 * address of memory image and return a pointer to the data, otherwise
 * return NULL.
 * The returned data must be freed by the caller.
 */
static uint8_t*
dump_process_memory(pid_t pid, Elf_Addr phdr_absolute_addr, size_t phdr_len,
                    size_t* size, Elf_Addr* load_addr)
{
    Elf_Phdr* phdr = calloc(phdr_len, sizeof(Elf_Phdr));
    uint8_t* data = NULL;
    size_t data_size = 0;

    Elf_Addr base_addr = 0;
    bool is_pie = false;

    if (phdr == NULL) {
        report_error("can't allocate memory for program headers");
        goto error;
    }

    if (attach_to_process(pid) < 0)
        goto error;

    for (size_t i = 0; i < phdr_len; i++) {
        /* Get current phdr */
        if (read_process_memory(pid, phdr_absolute_addr + sizeof(Elf_Phdr) * i,
                                &phdr[i], sizeof(Elf_Phdr)) < 0) {
            goto error;
        }

        if (phdr[i].p_type == PT_PHDR) {
            /*
             * If PT_PHDR is present we can easily get the base address
             * of PIE executable. If the executable is non-PIE, then
             * "base_addr" will be zero.
             */
            is_pie = phdr[i].p_vaddr < phdr_absolute_addr;
            base_addr = phdr_absolute_addr - phdr[i].p_vaddr;
        } else if (phdr[i].p_type == PT_LOAD) {
            Elf_Addr addr = phdr[i].p_vaddr;

            if (base_addr == 0) {
                is_pie = phdr[i].p_vaddr == 0;
                if (!is_pie) {
                    base_addr = phdr[i].p_vaddr;
                } else {
                    base_addr = find_elf_header(pid, phdr_absolute_addr);
                    if (base_addr == 0)
                        goto error;
                }
            }

            /* Realloc to max size of ELF */
            if (data_size < phdr[i].p_offset + phdr[i].p_filesz) {
                size_t old_data_size = data_size;

                data_size = phdr[i].p_offset + phdr[i].p_filesz;
                data = realloc(data, data_size);
                if (data == NULL)
                    goto error;

                memset(data + old_data_size, 0, data_size - old_data_size);
            }

            /* Dump LOAD segment */
            if (read_process_memory(pid, is_pie ? base_addr + addr : addr,
                                    data + phdr[i].p_offset,
                                    phdr[i].p_filesz) < 0) {
                goto error;
            }

            if (verbose) {
                report_info("dumped LOAD segment at 0x%08lx of %lu bytes",
                            base_addr + phdr[i].p_vaddr, phdr[i].p_filesz);
            }
        }
    }

    if (detach_from_process(pid) < 0)
        goto error;

    *size = data_size;
    *load_addr = base_addr;

    free(phdr);
    return data;

 error:
    free(phdr);
    free(data);

    return NULL;
}


static void
rebuild_elf_header(Elf_Ehdr* ehdr)
{
    ehdr->e_shnum = 0;
    ehdr->e_shentsize = 0;
    ehdr->e_shoff = 0;
    ehdr->e_shstrndx = 0;
}


/*
 * Find index of dynamic segment header in "phdr[phdr_len]". Returns the
 * index of dynamic segment header on success, 0 on failure.
 */
static size_t
find_dynamic_program_header(const Elf_Phdr* phdr, size_t phdr_len)
{
    size_t dynamic = 0;

    while (dynamic < phdr_len && phdr[dynamic].p_type != PT_DYNAMIC)
        dynamic++;

    return dynamic == phdr_len ? 0 : dynamic;
}


/* Undo relocations "rel[len]" in binary data. */
static void
undo_rel_relocations(const Elf_Rel* rel, size_t len, Elf_Off data_offset,
                     Elf_Addr base_addr, bool is_pie, const uint8_t* data)
{
    for (size_t i = 0; i < len; i++) {
        Elf_Addr* val = NULL;
        Elf_Off offset = rel[i].r_offset - data_offset;

        if (!is_pie)
            offset -= base_addr;

        val = (Elf_Addr*) (data + offset);

        /* TODO: R_DIRECT relocation type */

        switch (ELF_R_TYPE(rel[i].r_info))
        {
        case R_GLOB_DAT:
            *val = 0;
            break;

        case R_RELATIVE:
            /*
             * After relocation, the value is:
             *     base_addr + addend
             * 
             * The value before relocation is addend:
             *     *val - base_addr
             */
            *val -= base_addr;
            break;

        case R_COPY:
        case R_NONE:
            break;

        default:
            report_warning("unsupported relocation type: %d",
                           ELF_R_TYPE(rel[i].r_info));
            break;
        }
    }
}


/* Undo relocations "rela[len]" in binary data. */
static void
undo_rela_relocations(const Elf_Rela* rela, size_t len, Elf_Off data_offset,
                      Elf_Addr base_addr, bool is_pie, const uint8_t* data)
{
    for (size_t i = 0; i < len; i++) {
        Elf_Addr* val = NULL;
        Elf_Off offset = rela[i].r_offset - data_offset;

        if (!is_pie)
            offset -= base_addr;

        val = (Elf_Addr*) (data + offset);
        switch (ELF_R_TYPE(rela[i].r_info))
        {
        case R_DIRECT:
        case R_GLOB_DAT:
            *val = 0;
            break;

        case R_RELATIVE:
            *val = rela[i].r_addend;
            break;

        case R_COPY:
        case R_NONE:
            break;

        default:
            report_warning("unsupported relocation type: %d",
                           ELF_R_TYPE(rela[i].r_info));
            break;
        }
    }
}


static void
undo_relocations(Elf_Off offset, size_t len, bool with_addend,
                 Elf_Off data_offset, Elf_Addr base_addr, bool is_pie,
                 const uint8_t* data)
{
    if (with_addend) {
        Elf_Rela* rela = (Elf_Rela*) (data + offset);
        undo_rela_relocations(rela, len, data_offset, base_addr, is_pie, data);
    } else {
        Elf_Rel* rel = (Elf_Rel*) (data + offset);
        undo_rel_relocations(rel, len, data_offset, base_addr, is_pie, data);
    }
}


/*
 * Find the PLT in text segment, specified by the offset "segment_offset" and
 * the size "segment_size".
 * Returns the PLT offset on success, 0 on failure.
 */
static Elf_Off
find_plt_section(Elf_Off text_segment_offset, size_t text_segment_size,
                 Elf_Addr got_relative_addr, Elf_Addr base_addr,
                 const uint8_t* data)
{
    const size_t push_size = 6;
    const uint8_t* plt = data + text_segment_offset;

    /* The PUSH instruction in PLT[0] entry pushes GOT[1] */
    Elf_Word target_addr = got_relative_addr + sizeof(Elf_Addr);

    /* Iterate through the segment to find the PUSH GOT[1] signature */
    for (size_t i = 0; i + push_size < text_segment_size; i++) {
        Elf_Word plt_offset = text_segment_offset + i;
        Elf_Word push_addr = *((Elf_Word*) &plt[i + 2]);
#ifdef __x86_64__
        if (plt[i] == 0xff && plt[i + 1] == 0x35 &&
            push_addr == target_addr - plt_offset - push_size)
            return plt_offset;
#endif
#ifdef __i386__
        bool imm = push_addr == target_addr + base_addr;
        bool got_plus_imm = push_addr == sizeof(Elf_Addr);

        if ((plt[i] == 0xff && plt[i + 1] == 0x35 && imm) ||
            (plt[i] == 0xff && plt[i + 1] == 0xb3 && got_plus_imm))
            return plt_offset;
#endif
    }

    return 0;
}


/*
 * Rebuild "len" + 3 entries of "got". Don't include GOT[0], GOT[1],
 * GOT[2] in "len".
 */
static void
rebuild_got(Elf_Addr* got, size_t len, Elf_Off plt_offset, Elf_Addr base_addr,
            bool is_pie, const uint8_t* data)
{
    got[1] = 0;
    got[2] = 0;

    for (size_t i = 3; i < len + 3; i++) {
        Elf_Addr val = plt_offset + 0x10 * (i - 2);
        bool is_ibt = data[val] == 0xf3 && data[val + 1] == 0x0f &&
#ifdef __x86_64__
                      data[val + 2] == 0x1e && data[val + 3] == 0xfa;
#endif
#ifdef __i386__
                      data[val + 2] == 0x1e && data[val + 3] == 0xfb;
#endif

        got[i] = is_ibt ? val : val + 6;
        if (!is_pie)
            got[i] += base_addr;
    }
}


static int
rebuild_dynamic(Elf_Dyn* dyn, Elf_Addr base_addr, const uint8_t* data)
{
    Elf_Ehdr* ehdr = (Elf_Ehdr*) data;
    Elf_Phdr* phdr = (Elf_Phdr*) (data + ehdr->e_phoff);
    Elf_Addr* got = NULL;

    Elf_Off data_offset = 0;
    Elf_Off plt_offset = 0;
    Elf_Addr max_absolute_addr = 0;
    Elf_Addr rel_relative_addr = 0;
    Elf_Addr got_relative_addr = 0;

    size_t rel_size = 0;
    size_t rel_entity_size = 0;
    size_t relplt_size = 0;
    size_t text_segment = 0;

    bool is_pie = false;
    bool with_addend = false;

    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        if (phdr[i].p_vaddr == 0)
            is_pie = true;

        max_absolute_addr = phdr[i].p_vaddr + phdr[i].p_filesz;
        if (phdr[i].p_flags & PF_X) {
            text_segment = i;
        } else if (phdr[i].p_flags & PF_W) {
            data_offset = phdr[i].p_vaddr - phdr[i].p_offset;
        }
    }

    if (is_pie) {
        max_absolute_addr += base_addr;
    } else {
        data_offset -= base_addr;
    }

    for (size_t i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag)
        {
        case DT_REL:
        case DT_RELA:
            rel_relative_addr = dyn[i].d_un.d_ptr - base_addr;
            break;

        case DT_RELENT:
        case DT_RELAENT:
            rel_entity_size = dyn[i].d_un.d_val;
            break;

        case DT_RELSZ:
        case DT_RELASZ:
            rel_size = dyn[i].d_un.d_val;
            break;

        case DT_PLTRELSZ:
            relplt_size = dyn[i].d_un.d_val;
            break;

        case DT_PLTGOT:
            got_relative_addr = dyn[i].d_un.d_ptr - base_addr;
            got = (Elf_Addr*) (data + got_relative_addr - data_offset);
            break;

        case DT_PLTREL:
            with_addend = dyn[i].d_un.d_val == DT_RELA;
            break;

        case DT_DEBUG:
            dyn[i].d_un.d_ptr = 0;
            break;

        default:
            break;
        }

        if (is_pie && dyn[i].d_un.d_ptr > base_addr &&
            dyn[i].d_un.d_ptr < max_absolute_addr)
            dyn[i].d_un.d_ptr -= base_addr;
    }

    if (!is_rel_entity_size_valid(rel_size, rel_entity_size, with_addend) ||
        !is_rel_entity_size_valid(relplt_size, rel_entity_size, with_addend)) {
        report_error("invalid relocation entity size");
        return -1;
    }

    undo_relocations(rel_relative_addr, rel_size / rel_entity_size,
                     with_addend, data_offset, base_addr, is_pie, data);

    if (verbose)
        report_info("undid relocations");

    plt_offset = find_plt_section(phdr[text_segment].p_offset,
                                  phdr[text_segment].p_filesz,
                                  got_relative_addr, base_addr, data);
    if (plt_offset == 0) {
        report_warning("can't find PLT");
    } else {
        size_t got_len = relplt_size / rel_entity_size;
        rebuild_got(got, got_len, plt_offset, base_addr, is_pie, data);

        if (verbose)
            report_info("rebuilt GOT");
    }

    return 0;
}


static int
rebuild_binary(Elf_Addr base_addr, uint8_t* data)
{
    Elf_Ehdr* ehdr = (Elf_Ehdr*) data;
    Elf_Phdr* phdr = (Elf_Phdr*) (data + ehdr->e_phoff);
    Elf_Dyn* dyn = NULL;

    size_t dynamic_segment = 0;

    rebuild_elf_header(ehdr);

    dynamic_segment = find_dynamic_program_header(phdr, ehdr->e_phnum);
    if (dynamic_segment == 0) {
        if (ehdr->e_type == ET_DYN) {
            report_error("can't find DYNAMIC segment");
            return -1;
        }

        return 0;
    }

    dyn = (Elf_Dyn*) (data + phdr[dynamic_segment].p_offset);
    if (rebuild_dynamic(dyn, base_addr, data) < 0)
        return -1;

    return 0;
}


/* Returns 0 on success, -1 on failure */
static int
create_executable(const char* path, const uint8_t* data, size_t size)
{
    int ret = -1;
    FILE* elf = fopen(path, "w");
    unsigned int mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP |
                        S_IROTH | S_IXOTH;

    if (elf == NULL) {
        report_error("can't open '%s': %s", path, strerror(errno));
        goto cleanup;
    } else if (fwrite(data, 1, size, elf) != size) {
        report_error("can't write to '%s': %s", path, strerror(errno));
        goto cleanup;
    }

    if (chmod(path, mode) < 0) {
        report_error("can't set permissions for '%s': %s", path,
                     strerror(errno));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (elf != NULL)
        fclose(elf);

    return ret;
}


static void
usage(int status)
{
    if (status != EXIT_SUCCESS) {
        fprintf(stderr, "Try '%s --help' for more information.\n",
                program_name);
    } else {
        printf("Usage: %s [options] [-p pid] [-o output_file]\n"
               "\n"
               "Recover an ELF executable from process dump.\n"
               "\n"
               "Options:\n"
               "    -h, --help              display this help and exit\n"
               "    -v, --verbose           explain what is being done\n"
               "    -p, --pid               process PID\n"
               "    -o <file>               output file\n",
               program_name);
    }
}


int
main(int argc, char* argv[])
{
    int ret = EXIT_FAILURE;

    pid_t pid = 0;
    char* out_path = NULL;

    uint8_t* data = NULL;

    Elf_Addr phdr_absolute_addr = 0;
    Elf_Addr base_addr = 0;

    size_t phdr_len = 0;
    size_t phdr_entity_size = 0;
    size_t data_size = 0;

    char c = 0;
    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"verbose", no_argument, &verbose, 'v'},
        {"pid", required_argument, NULL, 'p'},
        {NULL, 0, NULL, 0}
    };
    int option_index = 0;

    program_name = argv[0];

    while ((c = getopt_long(argc, argv, "hvp:o:", long_options,
                            &option_index)) != -1) {
        switch(c) {
        case 0:
            if (long_options[option_index].flag != 0)
                break;
            
            if (long_options[option_index].has_arg && optarg == NULL) {
                report_error("no pid");
                usage(EXIT_FAILURE);
                goto cleanup;
            } else if ((pid = atoi(optarg)) == 0) {
                report_error("invalid pid");
                goto cleanup;
            }
            break;

        case 'h':
            usage(EXIT_SUCCESS);
            ret = EXIT_SUCCESS;
            goto cleanup;

        case 'v':
            verbose = 1;
            break;

        case 'p':
            if ((pid = atoi(optarg)) == 0) {
                report_error("invalid pid");
                goto cleanup;
            }
            break;

        case 'o':
            out_path = optarg;
            break;

        default:
            usage(EXIT_FAILURE);
            goto cleanup;
        }
    }

    if (pid == 0) {
        report_error("no pid");
        usage(EXIT_FAILURE);
        goto cleanup;
    } else if (out_path == NULL) {
        report_error("no output file");
        usage(EXIT_FAILURE);
        goto cleanup;
    }

    if (!process_exists(pid)) {
        report_error("process with the given pid does not exist");
        goto cleanup;
    }

    if (get_binary_information(pid, &phdr_absolute_addr, &phdr_len,
                               &phdr_entity_size) < 0) {
        goto cleanup;
    } else if (phdr_absolute_addr == 0 || phdr_len == 0) {
        report_error("can't find program headers");
        goto cleanup;
    } else if (!is_phdr_entity_size_valid(phdr_entity_size)) {
        report_error("invalid program header entity size");
        goto cleanup;
    }

    data = dump_process_memory(pid, phdr_absolute_addr, phdr_len, &data_size,
                               &base_addr);
    if (data == NULL)
        goto cleanup;

    if (rebuild_binary(base_addr, data) < 0)
        goto cleanup;

    if (create_executable(out_path, data, data_size) < 0)
        goto cleanup;

    if (verbose)
        report_info("saved %lu bytes into '%s'", data_size, out_path);

    ret = EXIT_SUCCESS;

 cleanup:
    free(data);

    return ret;
}
