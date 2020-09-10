// echo $$  # print pid of current shell

// provider:module:function:name

syscall::read:entry,
syscall::write:entry,
syscall::read_nocancel:entry,
syscall::write_nocancel:entry
/pid == $1/         // dtrace -s script <pid>
{
    printf("%s(%d, 0x%x, %4d)", probefunc, arg0, arg1, arg2); // probe arguments
}

syscall::read:return,
syscall::write:return,
syscall::read_nocancel:return,
syscall::write_nocancel:return
/pid == $1/         // argument #1
{
    printf("    = %d %d", arg0, arg1); // probe arguments
}


/*
  957    syscall                                      write_nocancel entry

	Argument Types
		args[0]: int
		args[1]: user_addr_t
		args[2]: user_size_t

  958    syscall                                      write_nocancel return

	Argument Types
		args[0]: user_ssize_t
		args[1]: user_ssize_t
*/
