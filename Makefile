DTRACE := dtrace

.PHONY: hello
hello:
	$(DTRACE) -s hello.d

.PHONY: trace_shell_io
trace_shell_io:
	$(DTRACE) -s io.d

.PHONY: list_probes
list_probes:
	$(DTRACE) -l

.PHONY: report_connect_args
report_connect_args:
	$(DTRACE) -lv \
		-i syscall::connect_nocancel:entry \
		-i syscall::connect_nocancel:return \
		-i syscall::connect:entry \
		-i syscall::connect:return
