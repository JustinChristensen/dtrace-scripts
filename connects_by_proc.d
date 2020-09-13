syscall::connect:entry,
syscall::connect_nocancel:entry
{
    @execs[execname] = count();
}

