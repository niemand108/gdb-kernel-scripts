import gdb

from linux import utils

VM_EXEC = 0x4
task_type = utils.CachedType("struct task_struct")


def task_lists():
    task_ptr_type = task_type.get_type().pointer()
    init_task = gdb.parse_and_eval("init_task").address
    t = g = init_task

    while True:
        while True:
            yield t

            t = utils.container_of(t['thread_group']['next'],
                                   task_ptr_type, "thread_group")
            if t == g:
                break

        t = g = utils.container_of(g['tasks']['next'],
                                   task_ptr_type, "tasks")
        if t == init_task:
            return


def task_name(name):
    for task in task_lists():
        if name in task['comm'].string():
            return task
    return None


def task_address(address):
    addr = int(address, 16)
    for task in task_lists():
        if addr == task:
            return task
    return None


class LxTskNameFunc(gdb.Function):

    def __init__(self):
        super(LxTskNameFunc, self).__init__("lx_task_by_name")

    def invoke(self, name):
        task = task_name(name)
        if task:
            return task.dereference()
        else:
            raise gdb.GdbError("No task with name" + str(name))


LxTskNameFunc()


class PtRegs(gdb.Command):
    """Ptregs by name."""

    def __init__(self):
        super(PtRegs, self).__init__("pt_regs", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) >= 1:
            try:
                name = str(argv[0])
            except:
                raise gdb.GdbError("Error str Name")
            task = task_name(name)
            if task:
                gdb.execute(
                    "set $stack = ((struct task_struct*) {address})->stack".format(address=task))
                gdb.execute(
                    "set $pt_regs=((struct pt_regs *) ($stack +16384))")
                gdb.execute("set $pt_regs_final = $pt_regs - 1")
                gdb.execute("p/x *$pt_regs_final")
                stck = gdb.parse_and_eval('$pt_regs_final')
            else:
                raise gdb.GdbError("No task with that name " + name)
        else:
            raise gdb.GdbError("Provide a Name")


PtRegs()

task_struct_santi = utils.CachedType("struct task_struct")
vm_area_struct_santi = utils.CachedType("struct vm_area_struct")
mm_struct_santi = utils.CachedType("struct mm_struct")
char_ptr = gdb.lookup_type('char').pointer()


def addr_in_range(addr, range_start, range_end):
    if addr >= range_start and addr <= range_end:
        return True
    else:
        return False


def range_in_range(range1_start, range1_end, range2_start, range2_end):
    return addr_in_range(range1_start, range2_start, range2_end) and \
        addr_in_range(range1_end, range2_start, range2_end)


class ExamineFault(gdb.Command):
    def __init__(self):
        super(ExamineFault, self).__init__("examine_fault", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        owner = gdb.parse_and_eval("vma->vm_mm->owner")
        task_name = task_address(hex(owner))['comm'].string()
        is_exec = gdb.parse_and_eval(
            "vma->vm_flags").cast(gdb.lookup_type("unsigned long")) & VM_EXEC
        address = hex(gdb.parse_and_eval(
            "address").cast(gdb.lookup_type("unsigned long")))
        gdb.write("this fault own to " + task_name.upper() +
                  " at address [" + address + "]\n")
        if is_exec:
            gdb.write("vma IS X\n")
        else:
            gdb.write("vma NOT IS X\n")


ExamineFault()


class MapProc(gdb.Command):
    def __init__(self):
        super(MapProc, self).__init__("map_proc", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) >= 1:
            try:
                name = str(argv[0])
            except:
                raise gdb.GdbError("Error str Name")
            task = task_name(name)
            if task:
                ret = task
                task_ptr = task_struct_santi.get_type().pointer()
                vm_area_ptr = vm_area_struct_santi.get_type().pointer()
                mm_struct_ptr = mm_struct_santi.get_type().pointer()
                task.cast(task_ptr)
                mm_struct = task['mm'].cast(mm_struct_ptr)
                vma = mm_struct['mmap'].cast(vm_area_ptr)
                gdb.write(
                    "[{start} - {end}]\n".format(start=hex(vma['vm_start']), end=hex(vma['vm_end'])))
                while int(vma['vm_next']) != 0:
                    vma = vma['vm_next'].cast(vm_area_ptr)
                    range_column = "[{start} - {end}]".format(
                        start=hex(vma['vm_start']), end=hex(vma['vm_end']))
                    gdb.write(range_column)
                    if vma['vm_flags'] & VM_EXEC:
                        gdb.write(" X ")
                    if int(vma['vm_file']) != 0:
                        file_ = gdb.parse_and_eval(
                            "((struct file *) {vm_file})->f_path->dentry->d_name->name".format(vm_file=hex(vma['vm_file'])))
                        filename = file_.cast(char_ptr).string()
                        gdb.write("\t{filename}".format(
                            filename=filename))
                    else:
                        if addr_in_range(mm_struct['start_stack'], vma['vm_start'], vma['vm_end']):
                            gdb.write("\n{tab}STACK start at {start}".format(
                                tab="\t".rjust(len(range_column)),
                                start=hex(mm_struct['start_stack'])))
                        if addr_in_range(mm_struct['arg_start'], vma['vm_start'], vma['vm_end']):
                            if not range_in_range(mm_struct['arg_start'], mm_struct['arg_end'], vma['vm_start'], vma['vm_end']):
                                gdb.write("\targs OVER limits!")
                            else:
                                gdb.write("\n{tab}args [{start}, {end}] ".format(
                                    tab="\t".rjust(len(range_column)), start=hex(mm_struct['arg_start']), end=hex(mm_struct['arg_end'])))

                        if addr_in_range(mm_struct['env_start'], vma['vm_start'], vma['vm_end']):
                            if not range_in_range(mm_struct['env_start'], mm_struct['env_end'], vma['vm_start'], vma['vm_end']):
                                gdb.write("\tenvs OVER limits!")
                            else:
                                gdb.write("\n{tab}envs [{start}, {end}] ".format(
                                    tab="\t".rjust(len(range_column)),
                                    start=hex(mm_struct['env_start']), end=hex(mm_struct['env_end'])))

                    gdb.write("\n")

            else:
                raise gdb.GdbError("No task with that name " + name)
        else:
            raise gdb.GdbError("Provide a Name")


MapProc()


class TaskPointer(gdb.Command):
    def __init__(self):
        super(TaskPointer, self).__init__("task_pointer", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) >= 1:
            try:
                name = str(argv[0])
            except:
                raise gdb.GdbError("Error str Name")
            is_addr = False
            if name.startswith("0x"):
                is_addr = True
                task = task_address(name)
            else:
                task = task_name(name)
            if task:
                if is_addr:
                    gdb.write("{name}\n".format(name=task['comm'].string()))
                else:
                    gdb.write("{addr}\n".format(addr=task))

            else:
                raise gdb.GdbError("No task with that name/address " + name)
        else:
            raise gdb.GdbError("Provide a Name/Address")


TaskPointer()
