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
	$(DTRACE) -lv \
		-i syscall::connect_nocancel:entry \
		-i syscall::connect_nocancel:return \
		-i syscall::connect:entry \
		-i syscall::connect:return

.PHONY: list_dtrace_consumers
list_dtrace_consumers:
	apropos dtrace

