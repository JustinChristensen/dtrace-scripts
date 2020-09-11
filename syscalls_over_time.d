proc:::exec-success
/execname == "date"/
{
	self->start = vtimestamp;
}

syscall:::entry
/self->start/
{
	@times["system calls over time"] =
	    lquantize((vtimestamp - self->start) / 1000, 0, 10000, 100);
    @calls[probefunc] = count()
}

syscall::exit:entry
/self->start/
{
	self->start = 0;
}
