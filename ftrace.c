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
#include <assert.h>

extern int insn_cmp(const void *a, const void *b);
extern int sym_cmp(const void *a, const void *b);
extern int sym_find(const void *key, const void *data);
extern int sec_cmp(const void *a, const void *b);

typedef int (*cmp_t)(const void *a, const void *b);

typedef struct vector {
	size_t size;
	size_t count;
	void **array;
	cmp_t cmp;
	cmp_t finder;
} vector_t;

void vector_init(vector_t *vec, cmp_t cmp)
{
	vec->size = 16;
	vec->count = 0;
	vec->array = malloc(vec->size * sizeof(void *));
	vec->cmp = cmp;
	vec->finder = cmp;
}

void vector_finder(vector_t *vec, cmp_t finder)
{
	vec->finder = finder;
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

int vector_add_uniq(vector_t *vec, void *obj)
{
	size_t i;

	for (i = 0; i < vec->count; ++i) {
		if (vec->cmp(&obj, &(vec->array[i])) == 0)
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


void vector_sort(vector_t *vec)
{
	qsort(vec->array, vec->count, sizeof(void *), vec->cmp);	
}

void *vector_search(vector_t *vec, const void *key)
{
	void **entry;
	entry = bsearch(&key, vec->array, vec->count, sizeof(void *), vec->finder);
	if (!entry)
		return NULL;

	return *entry;
}

struct insn {
        struct ud ud;
        unsigned long address;
        unsigned int length;
        unsigned char old_insn[16];
        int (*executor)(struct insn *insn, pid_t process, struct user_regs_struct *gpregs);
};

struct section {
	char name[32];
	unsigned long address;
	unsigned long length;
	vector_t insn_vec;
	struct elf_obj *elf_obj;
};

struct section * new_section(char *name, unsigned long address,
			unsigned long length, struct elf_obj *elf)
{
	struct section *sec;

	sec = malloc(sizeof(struct section));
	if (sec) {
		strncpy(sec->name, name, sizeof(sec->name) - 1);
		sec->name[sizeof(sec->name) - 1] = '\0';
		sec->address = address;
		sec->length = length;
		sec->elf_obj = elf;
		vector_init(&sec->insn_vec, insn_cmp);
	}

	return sec;
}

void free_section(struct section *sec)
{
	free(sec);
}

int sec_cmp(const void *a, const void *b)
{
	const void * const *pa = a;
	const void * const *pb = b;

	const struct section *seca = *pa;
	const struct section *secb = *pb;

	if (seca->address < secb->address)
		return -1;

	if (seca->address > secb->address)
		return 1;

	return 0;
}

int sec_find(const void *key, const void *data)
{
	const void * const *pkey = key;
	unsigned long lkey = (unsigned long)(*pkey);

	const void *const *pd = data;
	const struct section *sec = *pd;

	if (lkey < sec->address)
		return -1;

	if (lkey >= sec->address + sec->length)
		return 1;

	return 0;
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
		vector_init(&elf->code_sec, NULL);
	}

	return elf;
}

void free_elf_obj(struct elf_obj *elf)
{
	vector_fini(&elf->code_sec);
	free(elf);
}

int elf_obj_cmp(const void *a, const void *b)
{
	const void * const *pa = a;
	const void * const *pb = b;
	
	const struct elf_obj *oa = *pa;
	const struct elf_obj *ob = *pb;

	return strcmp(oa->file, ob->file);
}

struct sym {
	unsigned long address;
	unsigned long size;
	char *name;
	struct elf_obj *elf_obj;
};

struct sym * new_sym(unsigned long address, unsigned long size,
		const char *name, struct elf_obj *elf)
{
	struct sym * sym;

	sym = malloc(sizeof(struct sym));
	if (!sym)
		return sym;

	sym->address = address;
	sym->size = size;
	sym->name = strdup(name);
	sym->elf_obj = elf;

	if (!sym->name) {
		free(sym);
		sym = NULL;
	}

	return sym;
}



vector_t code_section_vec;
vector_t elf_obj_vec;
vector_t insn_vec;
vector_t sym_vec;

void all_init()
{
	vector_init(&code_section_vec, sec_cmp);
	vector_finder(&code_section_vec, sec_find);
	vector_init(&elf_obj_vec, elf_obj_cmp);
	vector_init(&insn_vec, insn_cmp);
	vector_init(&sym_vec, sym_cmp);
	vector_finder(&sym_vec, sym_find);
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

	if (ehdr_mem.e_type == ET_EXEC) {
		address = 0;  // exec elf, don't need to add a load address
	}

	elf_obj = new_elf_obj(file, address);	
	if (vector_add_uniq(&elf_obj_vec, elf_obj)) {
		// dup elf obj, don't add to vector, we should free here
		free_elf_obj(elf_obj);
		return 0;
	}

	// load elf execute section
	for (section = 0; section < ehdr_mem.e_shnum; ++section) {
		GElf_Shdr shdr_mem;
		Elf_Scn *scn = elf_getscn(elf, section);
		gelf_getshdr(scn, &shdr_mem);

		// this section contains instruction
		if (shdr_mem.sh_type == SHT_PROGBITS &&
			(shdr_mem.sh_flags & SHF_EXECINSTR)) {
			struct section *sec = new_section("<>", shdr_mem.sh_addr + address,
						shdr_mem.sh_size, elf_obj);

			vector_add(&code_section_vec, sec);
			vector_add(&elf_obj->code_sec, sec);
		}

		// this section is strtab section
		if (shdr_mem.sh_type == SHT_SYMTAB ||
			shdr_mem.sh_type == SHT_DYNSYM) {
			Elf_Data *symdata = elf_getdata(scn, NULL);
			GElf_Sym sym_mem;

			size_t nsym = symdata->d_size / sizeof(Elf64_Sym);
			size_t cnt;
			for (cnt = 0; cnt < nsym; ++cnt) {
				GElf_Sym *sym = gelf_getsym(symdata, cnt, &sym_mem);
				if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC
					&& sym->st_value != 0 
					&& sym->st_size != 0) {
					struct sym *psym = new_sym(sym->st_value + address,
							sym->st_size,
							elf_strptr(elf, shdr_mem.sh_link, sym->st_name),
							elf_obj);
					vector_add(&sym_vec, psym);
				}
			}
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

		start_address = strtoul(range, NULL, 16);		

		load_elf_file(start_address, file);
	}

	return 0;
}

int insn_cmp(const void *a, const void *b)
{
	const void * const *pa = a;
	const void * const *pb = b;

	const struct insn *ia = *pa;
	const struct insn *ib = *pb;

	if (ia->address > ib->address)
		return 1;

	if (ia->address < ib->address)
		return -1;

	return 0;
}

int sym_cmp(const void *a, const void *b)
{
	const void * const *pa = a;
	const void * const *pb = b;

	const struct sym * syma = *pa;
	const struct sym * symb = *pb;

	if (syma->address > symb->address)
		return 1;

	if (syma->address < symb->address)
		return -1;

	return 0;
}

int sym_find(const void *key, const void *data)
{
	const void *const *pd = data;
	const struct sym *sym = *pd;

	const void * const *pk = *(void **)key;
	unsigned long lkey = (unsigned long)pk;


	if (lkey < sym->address)
		return -1;

	if (lkey > sym->address)
		return 1;

	return 0;
}

void int3_fault_fixup_pre(struct user_regs_struct *gpregs)
{
	gpregs->rip -= 1;	
}

void int3_fault_fixup_post(struct user_regs_struct *gpregs, struct insn *insn)
{
	if (insn)
		gpregs->rip += insn->length;
	else
		gpregs->rip += 1;
}

int handle_int3_fault(unsigned long rip, struct user_regs_struct *gpregs, pid_t process)
{
	struct insn *insn;
	struct insn key;

	key.address = rip;

	insn = vector_search(&insn_vec, &key);
	int3_fault_fixup_post(gpregs, insn);
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

unsigned long reg_value(enum ud_type reg, struct user_regs_struct *gpregs)
{
	switch(reg) {
	case UD_NONE:
		return 0UL;
	case UD_R_RAX:
		return gpregs->rax;
	case UD_R_RCX:
		return gpregs->rcx;
	case UD_R_RDX:
		return gpregs->rdx;
	case UD_R_RBX:
		return gpregs->rbx;
	case UD_R_RSP:
		return gpregs->rsp;
	case UD_R_RBP:
		return gpregs->rbp;
	case UD_R_RSI:
		return gpregs->rsi;
	case UD_R_RDI:
		return gpregs->rdi;
	case UD_R_R8:
		return gpregs->r8;
	case UD_R_R9:
		return gpregs->r9;
	case UD_R_R10: 
		return gpregs->r10;
	case UD_R_R11:
		return gpregs->r11;
	case UD_R_R12:
		return gpregs->r12;
	case UD_R_R13:
		return gpregs->r13;
	case UD_R_R14:
		return gpregs->r14;
	case UD_R_R15:
		return gpregs->r15;
	case UD_R_RIP:
		return gpregs->rip;

	default:
		fprintf(stderr, "invalid regs %d\n", reg);
		abort();
	}
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
		unsigned long taddr;
		unsigned int base_reg = insn->ud.operand[0].base;
		unsigned int index_reg = insn->ud.operand[0].index;
		unsigned char scale = insn->ud.operand[0].scale;
		unsigned long offset;

		switch(insn->ud.operand[0].offset) {
		case 64:
			offset = insn->ud.operand[0].lval.uqword;
			break;
		case 32:
			offset = insn->ud.operand[0].lval.udword;
			break;
		case 16:
			offset = insn->ud.operand[0].lval.uword;
			break;
		case 8:
			offset = insn->ud.operand[0].lval.ubyte;
			break;
		case 0:
			offset = 0;
			break;
		default:
			abort();
		}

		taddr = reg_value(base_reg, gpregs) + reg_value(index_reg, gpregs) * scale + offset;
		assert(insn->ud.operand[0].size == 64);
		ptrace_read_text(process, taddr, insn->ud.operand[0].size, &target_pc);
	} else if (insn->ud.operand[0].type == UD_OP_REG) {
		unsigned int reg = insn->ud.operand[0].base;
		target_pc = reg_value(reg, gpregs);
	}

	struct sym *sym_caller, *sym_callee;
	struct section *sec_caller, *sec_callee;

	sym_caller = vector_search(&sym_vec, (void *)next_pc);
	if (!sym_caller)
			sec_caller = vector_search(&code_section_vec, (void *)next_pc);

	sym_callee = vector_search(&sym_vec, (void *)target_pc);
	if (!sym_callee)
			sec_callee = vector_search(&code_section_vec, (void *)target_pc);


	if (sym_caller)
		printf("caller: %lx %s %s\n", next_pc, sym_caller->name,
			sym_caller->elf_obj->file);
	else
		printf("caller: %lx %s\n", next_pc, sec_caller->elf_obj->file);

	if (sym_callee)
		printf("-->callee: %lx %s %s\n", target_pc, sym_callee->name,
			sym_callee->elf_obj->file);
	else
		printf("-->callee: %lx %s\n", target_pc, sec_callee->elf_obj->file);
	// begin to simulator call instruction
	// call instructio behavior as:
	// rsp sub 8
	// move next_pc to rsp
	// move target_pc to rip
	gpregs->rsp -= sizeof(long);
	gpregs->rip = target_pc;
	ptrace_write_text(process, gpregs->rsp, sizeof(long), &next_pc);	
	ptrace(PTRACE_SETREGS, process, NULL, gpregs);

	return 0;
}

int visit_code_section(void *obj, void *data)
{
	struct section *sec = obj;
	pid_t process = (pid_t)(unsigned long)data;
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
                if (ud.mnemonic == UD_Icall) {
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
                }
	}

	ret = 0;
fail:
	free(copy_mem);

	return ret;
}

void hook_sections(pid_t process)
{
	vector_sort(&code_section_vec);
	vector_visit(&code_section_vec, visit_code_section, (void *)(unsigned long)process);
	vector_sort(&insn_vec);
	vector_sort(&sym_vec);
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

				int3_fault_fixup_pre(&gpregs);
				child_handle = handle_int3_fault(gpregs.rip, &gpregs, child);
				ptrace(PTRACE_CONT, child, NULL, child_handle);
			}

		} else {
			printf("unknow status %d\n", status);
		}
	}
}
