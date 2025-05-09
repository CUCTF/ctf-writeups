import sys
import csv
import os
import numpy as np

if len(sys.argv) != 2:
    print('Usage: python disassembler.py <c_bytecode_file>')
    exit(1)

# Load spec
opcodes = {}
default_atoms = [None] # Atoms start at 1

# Color codes
BOLD = '\033[1m'
GRAY = '\033[90m'
YELLOW = '\033[93m'
RED = '\033[91m'
GREEN = '\033[92m'
CYAN = '\033[96m'
END = '\033[0m'

with open('../FlagSecurityEngine/opcodes.txt') as f:
    for line in f:
        op_name, op_code = (x.strip() for x in line.strip().split('='))
        
        opcodes[op_code] = {
            'name': op_name[3:],
            'code': op_code
        }

with open('quickjs/quickjs-atom.h') as f:
    for line in f:
        line = line.strip()
        if line.startswith('DEF('):
            name = line[4:].split(',')[1].split('"')[1]
            default_atoms.append(name)

def get_by_name(name):
    for opcode in opcodes.values():
        if opcode['name'] == name:
            return opcode

    return None

with open('quickjs/quickjs-opcode.h') as f:
    for line in f:
        line = line.strip()
        if line.startswith('DEF('):
            args = line[4:-1].split(')')[0].split(',')
            args = [arg.strip() for arg in args]
            
            if len(args) == 5:
                id, size, n_pop, n_push, f = args
            else:
                continue

            opcode = get_by_name(id)
            if opcode:
                opcode['size'] = int(size)
                opcode['n_pop'] = int(n_pop)
                opcode['n_push'] = int(n_push)
                opcode['f'] = f

def make_int(bytes):
    value = 0
    for i in range(len(bytes)):
        value |= (bytes[i] << (i * 8))
    return value

def disassemble(bytecode, atoms, local_vars, start_index):
    i = 0
    while i < len(bytecode):
        op = str(bytecode[i])
        if op in opcodes:
            if not 'size' in opcodes[op]:
                raise Exception(f'Opcode {op} has no size')
            
            size = int(opcodes[op]['size'])
            op_name = opcodes[op]['name']
            op_bytes = ' '.join(f'{byte:02x}' for byte in bytecode[i:i+size])
            if len(op_bytes) < 14:
                op_bytes += ' ' * (14 - len(op_bytes))

            print(f'  {GRAY}{(i + start_index):04x} {CYAN}{op_bytes} {YELLOW}{op_name}', end='')
            
            if size > 1:
                if opcodes[op]['f'] == 'atom_u8':
                    operand0 = make_int(bytecode[i+1:i+5])
                    operand1 = bytecode[i+5]
                    print(f' {RED}{operand0} {operand1}', end='')

                    var_name = atoms[operand0]
                    print(f' {GREEN}[{var_name}]', end='')
                else:
                    operand = make_int(bytecode[i+1:i+size])
                    print(f' {RED}{operand}', end='')

                    if opcodes[op]['f'] == 'atom':
                        var_name = atoms[operand]
                        print(f' {GREEN}[{var_name}]', end='')
                    if opcodes[op]['f'] == 'loc':
                        if operand < len(local_vars):
                            local_name = local_vars[operand]
                            print(f' {GREEN}[{local_name}]', end='')
                        else:
                            print(f' {RED}[invalid]', end='')

            elif op_name.startswith('put_loc') or op_name.startswith('get_loc'):
                loc_index = int(op_name[7:])
                if loc_index < len(local_vars):
                    local_name = local_vars[loc_index]
                    print(f' {GREEN}[{local_name}]', end='')
                else:
                    print(f' {RED}[invalid]', end='')

            print(END)

            i += size
        else:
            raise Exception(f'Unknown opcode {op}')

class BytecodeReader:
    def __init__(self, bytecode):
        self.bytecode = bytecode
        self.index = 0

    def read_u8(self):
        if self.index >= len(self.bytecode):
            raise Exception('Index out of range')
        value = self.bytecode[self.index]
        self.index += 1
        return value
    
    def read_u16(self):
        if self.index + 1 >= len(self.bytecode):
            raise Exception('Index out of range')
        value = (self.bytecode[self.index + 1] << 8) | self.bytecode[self.index]
        self.index += 2
        return value
    
    def read_u32(self):
        if self.index + 3 >= len(self.bytecode):
            raise Exception('Index out of range')
        value = (self.bytecode[self.index + 3] << 24) | (self.bytecode[self.index + 2] << 16) | (self.bytecode[self.index + 1] << 8) | self.bytecode[self.index]
        self.index += 4
        return value
    
    def read_u64(self):
        if self.index + 7 >= len(self.bytecode):
            raise Exception('Index out of range')
        value = (self.bytecode[self.index + 7] << 56) | (self.bytecode[self.index + 6] << 48) | (self.bytecode[self.index + 5] << 40) | (self.bytecode[self.index + 4] << 32) | (self.bytecode[self.index + 3] << 24) | (self.bytecode[self.index + 2] << 16) | (self.bytecode[self.index + 1] << 8) | self.bytecode[self.index]
        self.index += 8
        return value
    
    def read_leb128(self):
        value = 0
        shift = 0
        while True:
            byte = self.read_u8()
            value |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return value
    
    def read_sleb128(self):
        val = self.read_leb128()
        val = (val >> 1) ^ -(val & 1)
        return val
    
    def read_string(self, length, is_wide):
        if self.index + length >= len(self.bytecode):
            raise Exception('Index out of range')
        if is_wide:
            value = ''.join(chr(self.bytecode[i]) for i in range(self.index, self.index + length * 2, 2))
        else:
            value = ''.join(chr(self.bytecode[i]) for i in range(self.index, self.index + length))
        self.index += length * (2 if is_wide else 1)
        return value
    
    def read(self, length):
        if self.index + length > len(self.bytecode):
            raise Exception('Index out of range')
        value = self.bytecode[self.index:self.index + length]
        self.index += length
        return value

    def read_big_int(self):
        exp = self.read_sleb128()
        assert exp != 0 and exp != 1 and exp != 2
        l = self.read_leb128()
        n = l & 7
        data = self.read(n)
        limb = []
        for i in range(1 if n > 0 else 0, (l + 7) // 8):
            limb.append(self.read_u64())
        return exp, data, limb


def resolve_atom(atoms, atom_num):
    if atom_num & 1:
        return atom_num >> 1
    else:
        return atoms[atom_num >> 1]
    
def u64_to_float(num):
    return np.int64(num).view(np.float64)
    
def disassemble_func(bytecode, atoms, identation=0):
    flags = bytecode.read_u16()
    mode = bytecode.read_u8()
    func_name = resolve_atom(atoms, bytecode.read_leb128())
    arg_count = bytecode.read_leb128()
    var_count = bytecode.read_leb128()
    defined_arg_count = bytecode.read_leb128()
    stack_size = bytecode.read_leb128()
    closure_var_count = bytecode.read_leb128()
    cpool_count = bytecode.read_leb128()
    byte_code_len = bytecode.read_leb128()
    locals_count = bytecode.read_leb128()

    idnt = '  ' * identation

    # Print all of this
    print(f'{idnt}{BOLD}Metadata:{END}')
    print(f'{idnt}  Flags: {bin(flags)}')
    print(f'{idnt}  Mode: {mode}')
    print(f'{idnt}  Function name: {func_name}')
    print(f'{idnt}  Argument count: {arg_count}')
    print(f'{idnt}  Variable count: {var_count}')
    print(f'{idnt}  Defined argument count: {defined_arg_count}')
    print(f'{idnt}  Stack size: {stack_size}')
    print(f'{idnt}  Bytecode length: {byte_code_len}')

    has_debug = flags & (1 << 10) != 0
    local_vars = []

    print(f"\n{idnt}{BOLD}Locals:{END}")
    for i in range(locals_count):
        var_name = resolve_atom(atoms, bytecode.read_leb128())
        scope_level = bytecode.read_leb128()
        scope_next = bytecode.read_leb128()
        var_flags = bytecode.read_u8()
        local_vars.append(var_name)
        print(f"{idnt}  {var_name} (level={scope_level}, next={scope_next}, flags={bin(var_flags)})")

    print(f"\n{idnt}{BOLD}Closure vars:{END}")
    for i in range(closure_var_count):
        var_name = resolve_atom(atoms, bytecode.read_leb128())
        var_flags = bytecode.read_u8()
        print(f"{idnt} {var_name}")


    exec_code_index = bytecode.index
    exec_code = bytecode.read(byte_code_len)
    print(f"\n{idnt}{BOLD}Disasembly:{END}")
    disassemble(exec_code, atoms, local_vars, exec_code_index)

    if has_debug:
        print(f"\n{idnt}{BOLD}Debug info:{END}")
        dbg_filename = resolve_atom(atoms, bytecode.read_leb128())
        db_line_num = bytecode.read_leb128()
        dbg_pc2line_len = bytecode.read_leb128()

        if dbg_pc2line_len > 0:
            pc2line_buf = bytecode.read(dbg_pc2line_len)

        print(f'{idnt}  Filename: {dbg_filename}')
        print(f'{idnt}  Line number: {db_line_num}')
        print(f'{idnt}  PC2Line length: {dbg_pc2line_len}')

    print(f"\n{idnt}{BOLD}Constant pool:{END}")
    for i in range(cpool_count):
        ctag = bytecode.read_u8()
        if ctag == 12: # Function
            print(f"{idnt} - const{i} {{")
            disassemble_func(bytecode, atoms, identation + 1)
            print(f"{idnt} }}")
        elif ctag == 6: # Float64
            num = bytecode.read_u64()
            print(f'{idnt}  {i}: {u64_to_float(num)} (float)')
        elif ctag == 10: # BigInt
            bigint = bytecode.read_big_int()
            print(f'{idnt}  {i}: {bigint} (bigint)')
        else:
            raise Exception(f'Unsupported ctag {ctag}.')
        
    
def bc_from_c_file(c_file):
    bc_array = c_file.read().split('{')[1].split('}')[0].strip()
    bc_array = bc_array.split(',')
    bc_array = [x.strip() for x in bc_array]
    bc_array = [x for x in bc_array if x]
    return BytecodeReader([int(x, 16) for x in bc_array])

is_c_file = sys.argv[1].endswith('.c')
is_js_file = sys.argv[1].endswith('.js')
is_binary_file = not is_c_file and not is_js_file
with open(sys.argv[1], 'rb' if is_binary_file else 'r') as f:
    if is_c_file:
        bytecode = bc_from_c_file(f)
    elif is_js_file:
        # Compile JS into c file
        c_file_name = sys.argv[1].replace('.js', '') + '.c'
        os.system(f'quickjs/qjsc -c {sys.argv[1]} -o {c_file_name}')
        with open(c_file_name, 'r') as f:
            bytecode = bc_from_c_file(f)
        # os.remove(c_file_name)
    else:
        bytecode = BytecodeReader(list(f.read()))

    version = bytecode.read_u8()
    if version != 67:
        raise Exception(f'Invalid version {version}')
    

    atom_count = bytecode.read_leb128()
    atoms = [a for a in default_atoms]

    print(f'{BOLD}Atoms:{END}')

    for atom_index in range(atom_count):
        atom_name_meta = bytecode.read_leb128()
        atom_name_length = atom_name_meta >> 1
        is_wide = atom_name_meta & 1
        atom_name = bytecode.read_string(atom_name_length, is_wide)
        atoms.append(atom_name)
        print(f'  {atom_index + 1}: {atom_name}')

    tag = bytecode.read_u8()
    if tag != 12:
        raise Exception(f'Invalid tag {tag}. Only function bytecode is supported')

    print()
    disassemble_func(bytecode, atoms)

    print("\nBytes left:", len(bytecode.bytecode) - bytecode.index)

# bytecode.index = 0
# print(bytecode.bytecode[144:382])

# Save all opcods as CSV in format
# name, code, size, n_pop, n_push, f
# with open('opcodes.csv', 'w', newline='') as csvfile:
#     fieldnames = ['name', 'code', 'size', 'n_pop', 'n_push', 'f']
#     writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

#     writer.writeheader()
#     for opcode in opcodes.values():
#         if 'size' in opcode:
#             writer.writerow(opcode)