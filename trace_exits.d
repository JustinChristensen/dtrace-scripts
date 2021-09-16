#!/usr/bin/env dtrace -C -s

#pragma D option quiet

#define ARG_LIMIT 128

this user_addr_t *argp;

syscall::exit:entry
{
	this->is64Bit = curpsinfo->pr_dmodel == PR_MODEL_ILP32 ? 0 : 1;
	this->wordsize = this->is64Bit ? 8 : 4;

    this->argc = curpsinfo->pr_argc;
    this->argv_ptr = curpsinfo->pr_argv;

    printf("%Y | %3d | ", walltimestamp, args[0]);
}

syscall::exit:entry
/!this->argv_ptr/
{
    printf("%s ", execname);
}

#define PRINT_ARG                                                                    \
syscall::exit:entry                                                                  \
/this->argc && this->argv_ptr/                                                       \
{                                                                                    \
	this->argp = copyin(this->argv_ptr, this->wordsize);                             \
	this->arg = copyinstr(*this->argp, ARG_LIMIT);                                   \
    printf("%s%s ", this->arg, strlen(this->arg) > ARG_LIMIT - 1 ? " (...)" : "");   \
	this->argv_ptr += this->wordsize;                                                \
	this->argc--;                                                                    \
}

PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG
PRINT_ARG

syscall::exit:entry
{
    printf("\n");
}
