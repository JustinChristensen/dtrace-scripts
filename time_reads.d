self int t; // stored timestamp

syscall::read:entry,
syscall::read_nocancel:entry
{
    self->t = timestamp;
}

syscall::read:return,
syscall::read_nocancel:return
{
    printf("%d/%d (%s) spent %d nanoseconds in %s\n", pid, tid, execname, timestamp - self->t, probefunc);
    self->t = 0; // reclaim storage? this book says I need to reclaim storage
}

