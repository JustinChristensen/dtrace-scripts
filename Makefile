PROBES_TXT := probes.txt
DTRACE := sudo dtrace

.PHONY: hello
hello:
	$(DTRACE) -s hello.d

.PHONY: trace_shell_io
trace_shell_io:
	$(DTRACE) -q -s io.d

.PHONY: time_reads
time_reads:
	$(DTRACE) -q -s time_reads.d

$(PROBES_TXT):
	$(DTRACE) -l > $(PROBES_TXT)

.PHONY: list_connect_args
list_connect_args:
	$(DTRACE) -lv -i 'syscall::connect*:entry'

.PHONY: print_syscall_probes
print_syscall_probes:
	$(DTRACE) -l -P syscall

.PHONY: list_dtrace_consumers
list_dtrace_consumers:
	apropos dtrace

