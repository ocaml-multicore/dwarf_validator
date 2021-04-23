Using the DWARF validation tool
===============================

The DWARF validation tool in `eh_frame_check.py` is built on the artifact:
  https://zenodo.org/record/3369915#.X6kNPpP7RTa
as presented in:
  Reliable and Fast DWARF-based Unwinding (Artifact)
  Bastian, Théophile; Kell, Stephen; Zappa Nardelli, Francesco
  Proceedings of the ACM on Programming Languages, October 2019
  https://dl.acm.org/doi/10.1145/3360572

The tool operates by single stepping through the binary as it executes.
On each function call, it notes the return address. It then unwinds the
stack using the DWARF directives on each instruction and checks that it
matches the previous return address.

The tool is updated to handle:
 - PIC/PIE code as outputted by OCaml programs
 - the ability to select the functions for which validation is performed by
   setting the `interesting_functions` variable
 - an implementation of the DW_OP_deref and DW_OP_plus_uconst directives

You need to select your `interesting_functions` to avoid trying to single step
through `clock_gettime` (which will never terminate) and also to keep the
runtime manageable in the debugging loop.

The tool was used to flag segments in our effects testsuite for further manual
inspection.

To setup your machine, you will need python packages for Python3. These are
in the `requirements.txt` file and can be installed with
 $ pip3 install -r requirements.txt


To run the tool on a binary use:
 $ gdb -q -ex 'py arg_verbose = True' -ex 'py arg_debug = True' \
       -x /home/ctk21/foobar/dwarf_validation/eh_frame_check.py \
       testsuite/tests/effects/_ocamltest/tests/effects/test2/ocamlopt.byte/test2.opt
    &> log.out

Bad DWARF segments can be found by searching `log.out` for `BAD DWARF`.

There are certain aspects of the DWARF unwind this tool can not validate:
 - caml_runstack from 'callq *(%rbx)' through 'jmp *(%rbx)'
  We are returning from the frame; the old stack however *may not* be in
  the same place as when we entered the function
  (see tests/effects/test2.ml)
 - caml_perform and caml_resume
  We enter the function on one fiber and leave it on another; the return
  address can not be validated.


