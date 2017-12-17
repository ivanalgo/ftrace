#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <libudis86/extern.h>
#include <errno.h>
#include <sys/user.h>


typedef struct vector {
	size_t size;
	size_t count;
	void **array;
} vector_t;

void vector_init(vector_t *vec)
{
	vec->size = 16;
	vec->count = 0;
	vec->array = malloc(vec->size * sizeof(void *));
}

void vector_fini(vector_t *vec)
{
	free(vec->array);
	vec->array = NULL;
}

void vector_add(vector_t *vec, void *obj)
{
	if (vec->count == vec->size) {
		int newsize = vec->size * 2;
		void *newarray = realloc(vec->array, newsize * sizeof(void *));
		vec->array = newarray;
		vec->size = newsize;
	}

	vec->array[vec->count++] = obj;
}

int vector_add_uniq(vector_t *vec, void *obj, int (*cmp)(void *obj, void *entry))
{
	size_t i;

	for (i = 0; i < vec->count; ++i) {
		if (cmp(obj, vec->array[i]) == 0)
			return -1;
	}

	vector_add(vec, obj);
	return 0;
}

int vector_visit(vector_t *vec, int (*visitor)(void *obj, void *data), void *data)
{
	size_t i;

	for (i = 0; i != vec->count; ++i) {
		if (visitor(vec->array[i], data))
			return 1;
	}

	return 0;
}

void vector_sort(vector_t *vec, int (*cmp)(const void *a, const void *b))
{
	qsort(vec->array, vec->count, sizeof(void *), cmp);	
}

void *vector_search(vector_t *vec, const void *key,
		int (*cmp)(const void *a, const void *b))
{
	void **entry;
	entry = bsearch(&key, vec->array, vec->count, sizeof(void *), cmp);
	if (!entry)
		return NULL;

	return *entry;
}

struct insn {
        struct ud ud;
        unsigned long address;
        unsigned int length;
        char old_insn[16];
        int (*executor)(struct insn *insn, pid_t process, struct user_regs_struct *gpregs);
};

struct section {
	char name[32];
	unsigned long address;
	unsigned long length;
	vector_t insn_vec;
};

struct section * new_section(char *name, unsigned long address, unsigned long length)
{
	struct section *sec;

	sec = malloc(sizeof(struct section));
	if (sec) {
		strncpy(sec->name, name, sizeof(sec->name) - 1);
		sec->name[sizeof(sec->name) - 1] = '\0';
		sec->address = address;
		sec->length = length;
		vector_init(&sec->insn_vec);
	}

	return sec;
}

void free_section(struct section *sec)
{
	free(sec);
}

struct elf_obj {
	char file[256];
	unsigned long load_address;
	vector_t code_sec;
};

struct elf_obj * new_elf_obj(char *file, unsigned long addr)
{
	struct elf_obj *elf;

	elf = malloc(sizeof(struct elf_obj));
	if (elf) {
		strncpy(elf->file, file, sizeof(elf->file) - 1);
		elf->file[sizeof(elf->file) - 1] = '\0';
		elf->load_address = addr;
		vector_init(&elf->code_sec);
	}

	return elf;
}

void free_elf_obj(struct elf_obj *elf)
{
	vector_fini(&elf->code_sec);
	free(elf);
}

int elf_obj_cmp(void *a, void *b)
{
	struct elf_obj *oa = a;
	struct elf_obj *ob = b;

	return strcmp(oa->file, ob->file);
}

vector_t code_section_vec;
vector_t elf_obj_vec;
vector_t insn_vec;

void all_init()
{
	vector_init(&code_section_vec);
	vector_init(&elf_obj_vec);
	vector_init(&insn_vec);
}

int load_elf_file(unsigned long address, char *file)
{
	int fd;
	Elf *elf;
	GElf_Ehdr ehdr_mem;
	struct elf_obj *elf_obj;
	int section;

	elf_version (EV_CURRENT);
	if ((fd = open(file, O_RDONLY)) < 0) {
		fprintf(stderr, "open file %s error %m\n", file);
		return -1;
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (gelf_getehdr(elf, &ehdr_mem) == NULL) {
		printf("get elf head failed: %s\n", elf_errmsg (-1));
	}

	//printf("elf head:\n");
	//printf("elf type: %d\n", (int)ehdr_mem.e_type);

	if (ehdr_mem.e_type == ET_EXEC) {
		address = 0;  // exec elf, don't need to add a load address
	}

	elf_obj = new_elf_obj(file, address);	
	if (vector_add_uniq(&elf_obj_vec, elf_obj, elf_obj_cmp)) {
		// dup elf obj, don't add to vector, we should free here
		free_elf_obj(elf_obj);
		return 0;
	}

	// load elf execute section
	for (section = 0; section < ehdr_mem.e_shstrndx; ++section) {
		GElf_Shdr shdr_mem;
		Elf_Scn *scn = elf_getscn(elf, section);
		gelf_getshdr(scn, &shdr_mem);

		// this section contains instruction
		if (shdr_mem.sh_type == SHT_PROGBITS &&
			(shdr_mem.sh_flags & SHF_EXECINSTR)) {
			struct section *sec = new_section("<>", shdr_mem.sh_addr + address,
						shdr_mem.sh_size);

			vector_add(&code_section_vec, sec);
			vector_add(&elf_obj->code_sec, sec);
		}
	}	

	return 0;
}

int load_process_maps(pid_t process)
{
	char maps_file[256];
	FILE *fp;
	char line[512];

	snprintf(maps_file, sizeof(maps_file), "/proc/%d/maps", process);
	fp = fopen(maps_file, "r");
	if (!fp) {
		fprintf(stderr, "open file %s errno %m\n", maps_file);
		return -1;
	}

	while(fgets(line, sizeof(line), fp)) {
		/*
		 * maps file format as :
		 * 00400000-0040b000 r-xp 00000000 08:03 1310739 /bin/cat
		 */ 

		char range[64];
		char perm[12];
		char dummy1[32];
		char dummy2[32];
		char dummy3[32];
		char file[256];	
		int ret;
		unsigned long start_address;

		ret = sscanf(line, "%s %s %s %s %s %s", range, perm, dummy1, dummy2, dummy3, file);
		if (ret != 6)
			continue;

		/* 
		 * if file is [stack], [heap], [vsdo], [vsyscall],
		 * then it's not an elf file.
		 */
		if (strchr(file, '[') && strchr(file, ']'))
			continue;

		// for debug, skip ld
		//if (strstr(file, "ld"))
		//	continue;

		start_address = strtoul(range, NULL, 16);		
		printf("maps: %lx %s\n", start_address, file);

		load_elf_file(start_address, file);
	}

	return 0;
}

int insn_cmp(const void *a, const void *b)
{
	void **pa = a;
	void **pb = b;

	const struct insn *ia = *pa;
	const struct insn *ib = *pb;

	if (ia->address > ib->address)
		return 1;

	if (ia->address < ib->address)
		return -1;

	return 0;
}

void int3_fault_fixup(struct user_regs_struct *gpregs)
{
	gpregs->rip -= 1;	
}

int handle_int3_fault(unsigned long rip, struct user_regs_struct *gpregs, pid_t process)
{
	struct insn *insn;
	struct insn key;

	key.address = rip;

	//printf("int3 fault at %lx\n", rip);
	insn = vector_search(&insn_vec, &key, insn_cmp);
	if (!insn) {
		/*
		 * Process @process trap signal wasn't by our INT3
		 * let itself to handle this signal
		 */
		//printf("no found insn\n");
		return 1;
	}

	insn->executor(insn, process, gpregs);
	//printf("we should handle this trap\n");
	return 0;

}

#define PTRACE_ALIGN (sizeof(unsigned long)) 

int ptrace_read_text(pid_t process, unsigned long addr, unsigned length, void *data)
{
	unsigned long start;
	unsigned long end;
	void *buff;
	unsigned long offset;
	unsigned long ret;

	start = addr & (~(PTRACE_ALIGN -1));
	end = (addr + length + PTRACE_ALIGN - 1) & (~(PTRACE_ALIGN - 1)); 

	buff = malloc(end - start);
	if (!buff)
		return -1;

	for (offset = start; offset < end; offset += PTRACE_ALIGN) {
		ret = ptrace(PTRACE_PEEKTEXT, process,
				(void *)offset, NULL);
		if (errno) {
			ret = -errno;
			goto fail;
		}

		memcpy(buff + offset - start, &ret, sizeof(ret));	
	}

	memcpy(data, buff + (addr - start), length);
	ret = 0;
fail:
	free(buff);
	return ret;
}

int ptrace_write_text(pid_t process, unsigned long addr, unsigned length, void *data)
{
        unsigned long start;
        unsigned long end;
        unsigned char *buff;
        unsigned long offset;
	unsigned long val;
        int ret;

        start = addr & (~(PTRACE_ALIGN -1));
        end = (addr + length + PTRACE_ALIGN - 1) & (~(PTRACE_ALIGN - 1));

        buff = malloc(end - start);
        if (!buff)
                return -1;

	ptrace_read_text(process, start, end - start, buff);

#if 0
	printf("code %x:\n", start);
	int i;
	for (i = 0; i < end - start; ++i)
		printf("%02x ", buff[i]);
#endif 

        memcpy(buff + addr - start, data, length);
#if 0
	printf("\n to \n");
	for (i = 0; i < end - start; ++i)
		printf("%02x ", buff[i]);
	printf("\n");
#endif

        for (offset = start; offset < end; offset += PTRACE_ALIGN) {
		memcpy(&val, buff + (offset - start), PTRACE_ALIGN);
                ret = ptrace(PTRACE_POKETEXT, process,
                        (void *)offset, val);
                if (ret < 0)
                        goto fail;
        }

        ret = 0;
fail:
        free(buff);
        return ret;

}

int call_executor(struct insn *insn, pid_t process, struct user_regs_struct *gpregs)
{
	unsigned long next_pc;
	unsigned long target_pc;

	next_pc = insn->address + insn->length;

	if (insn->ud.operand[0].type  == UD_OP_JIMM) {
		const uint64_t trunc_mask = 0xffffffffffffffffull >> (64 - insn->ud.opr_mode);
		struct ud_operand *opr = &insn->ud.operand[0];

		switch(opr->size){
		case 8:
			target_pc = (next_pc + opr->lval.sbyte)  & trunc_mask;
			break;
		case 16:
			target_pc = (next_pc + opr->lval.sword)  & trunc_mask;
			break;
		case 32:
			target_pc = (next_pc + opr->lval.sdword) & trunc_mask;
			break;
		default:
			printf("Unknow operand size %d\n", opr->size);
			abort();
		}

		//printf("call imm\n");
	} else if (insn->ud.operand[0].type == UD_OP_MEM) {
		printf("another call\n");
		return 0;
	} else {
		printf("another call\n");
		return 0;
	}

	printf("Good: %lx call %lx\n", next_pc, target_pc);
	// begin to simulator call instruction
	// call instructio behavior as:
	// rsp sub 8
	// move next_pc to rsp
	// move target_pc to rip
	gpregs->rsp -= sizeof(long);
	gpregs->rip = target_pc;
	ptrace_write_text(process, gpregs->rsp, sizeof(long), &next_pc);	
	ptrace(PTRACE_SETREGS, process, NULL, gpregs);
}

int visit_code_section(void *obj, void *data)
{
	struct section *sec = obj;
	pid_t process = (pid_t)data;
	void *copy_mem;
	int ret;
	struct ud ud;

	copy_mem = malloc(sec->length);
	if (!copy_mem)
		return 1;

	if ((ret = ptrace_read_text(process, sec->address, sec->length, copy_mem) < 0))
		goto fail;

	ud_init(&ud);
	ud_set_mode(&ud, 64);
	ud_set_input_buffer(&ud, copy_mem, sec->length);
	while(ud_disassemble(&ud)) {
                if (ud.mnemonic == UD_Icall && ud.operand[0].type == UD_OP_JIMM) {
                        struct insn *insn = malloc(sizeof(struct insn));
			unsigned char bytes[16] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
				0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
				0xCC, 0xCC};
                        insn->address = sec->address + ud.insn_offset;
                        insn->length = ud.inp_ctr;
                        insn->ud = ud;
                        insn->executor = call_executor;
                        memcpy(insn->old_insn, copy_mem + ud.insn_offset, insn->length);
                        vector_add(&sec->insn_vec, insn);
			vector_add(&insn_vec, insn);
			ptrace_write_text(process, insn->address, insn->length, bytes);
			printf("hook code: [%lx - %lx]\n", insn->address, insn->address + insn->length);
                }
	}

	ret = 0;
fail:
	free(copy_mem);

	return ret;
}

void hook_sections(pid_t process)
{
	vector_visit(&code_section_vec, visit_code_section, (void *)process);
	vector_sort(&insn_vec, insn_cmp);
}

int main(int argc, char *argv[])
{
	pid_t child;
	int status;
	bool execved = 0;

	if (argc < 2) {
		fprintf(stderr, "useage: uftrace <options> <program> <args...>\n");
		exit(1);
	}

	child = fork();
	if (child == -1) {
		fprintf(stderr, "fork error %m\n");
		exit(1);
	}

	/* child */
	if (child == 0) {
		ptrace(PTRACE_TRACEME);
		execv(argv[1], argv + 1);
		_exit(127);
	}


	all_init();
	/* parent, debugger */
	while(1) {
		wait(&status);
		if (WIFEXITED(status)) {
			/* child exit */
			fprintf(stderr, "process %d exit...\n", child);
			exit(0);
		}

		if (WIFSIGNALED(status)) {
			/* child terminal by signal */
			fprintf(stderr, "process %d terminal by signal\n", child);
			exit(0);
		}

		if (WIFSTOPPED(status)) {
			int sig =  WSTOPSIG(status);
			//printf("stop signal %d\n", sig);
			if (sig != SIGTRAP) {
				ptrace(PTRACE_CONT, child, NULL, 1);
			} else if (!execved) {
				/* execve stop */
				execved = true; 
				load_process_maps(child);
				hook_sections(child);
				ptrace(PTRACE_CONT, child, NULL, NULL);
			} else {
				struct user_regs_struct gpregs;
				int child_handle;
				if (ptrace(PTRACE_GETREGS, child, NULL, &gpregs) < 0) {
					fprintf(stderr, "ptrace getregs failed %m\n");
				}

				int3_fault_fixup(&gpregs);
				//printf("RIP = %lx\n", gpregs.rip);
				child_handle = handle_int3_fault(gpregs.rip, &gpregs, child);
				ptrace(PTRACE_SINGLESTEP, child, NULL, 0);
			}

		} else {
			printf("unknow status %d\n", status);
		}
	}
}
