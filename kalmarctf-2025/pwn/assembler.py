import csv
import sys
import math
import os
import shlex
import numpy as np

# Byte code of the function float_add_raw
FLOAT_ADD_RAW_BC = [67, 6, 0, 198, 3, 2, 2, 2, 6, 0, 4, 169, 1, 4, 200, 3, 0, 1, 0, 202, 3, 0, 1, 0, 204, 3, 1, 0, 48, 226, 1, 1, 1,
                     32, 97, 1, 0, 97, 0, 0, 56, 179, 0, 0, 0, 17, 56, 166, 0, 0, 0, 17, 191, 8, 33, 1, 0, 33, 1, 0, 203, 98, 0, 0,
                     66, 231, 0, 0, 0, 183, 211, 10, 36, 3, 0, 14, 56, 180, 0, 0, 0, 98, 0, 0, 66, 232, 0, 0, 0, 187, 10, 36, 2, 0,
                     241, 193, 0, 161, 56, 180, 0, 0, 0, 98, 0, 0, 66, 232, 0, 0, 0, 183, 10, 36, 2, 0, 241, 176, 204, 98, 1, 0, 56,
                     180, 0, 0, 0, 212, 241, 158, 17, 99, 1, 0, 14, 98, 0, 0, 66, 233, 0, 0, 0, 183, 56, 154, 0, 0, 0, 98, 1, 0, 193,
                     1, 174, 241, 10, 36, 3, 0, 14, 98, 0, 0, 66, 233, 0, 0, 0, 187, 56, 154, 0, 0, 0, 98, 1, 0, 193, 2, 162, 193, 3,
                     174, 241, 10, 36, 3, 0, 14, 98, 0, 0, 66, 234, 0, 0, 0, 183, 10, 37, 2, 0, 202, 3, 1, 7, 34, 110, 80, 220, 85,
                     133, 150, 10, 36, 1, 128, 10, 140, 1, 4, 255, 255, 255, 255, 10, 36, 1, 128, 10, 140, 1, 4, 255, 255, 255, 255]

default_atoms = [None] # Atoms start at 1

class BytecodeWriter:
    def __init__(self):
        self.bytecode = []

    def write_u8(self, value):
        if not (0 <= value <= 255):
            raise Exception('Value out of range')
        self.bytecode.append(value)

    def write_u16(self, value):
        if not (0 <= value <= math.pow(2, 16) - 1):
            raise Exception('Value out of range')
        self.bytecode.append(value & 0xFF)
        self.bytecode.append((value >> 8) & 0xFF)

    def write_u32(self, value):
        self.bytecode.append(value & 0xFF)
        self.bytecode.append((value >> 8) & 0xFF)
        self.bytecode.append((value >> 16) & 0xFF)
        self.bytecode.append((value >> 24) & 0xFF)

    def write_u64(self, value):
        for i in range(8):
            self.bytecode.append((value >> (i * 8)) & 0xFF)

    def write_leb128(self, value):
        while True:
            byte = value & 0x7F
            value >>= 7
            if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
                self.write_u8(byte)
                break
            self.write_u8(byte | 0x80)

    def write_string(self, value, is_wide):
        if is_wide:
            for char in value:
                self.write_u16(ord(char))
        else:
            for char in value:
                self.write_u8(ord(char))

    def write(self, value):
        if isinstance(value, list):
            for item in value:
                if isinstance(item, int):
                    self.write_u8(item)
                elif isinstance(item, str):
                    self.write_string(item, False)
                else:
                    raise Exception('Invalid value type')
        else:
            raise Exception('Invalid value type')

with open('opcodes.csv') as f:
    reader = csv.reader(f)

    # Skip first row
    next(reader)

    opcodes = {row[0]: {'name': row[0], 'code': int(row[1]), 'size': int(row[2]), 'n_pop': int(row[3]), 'n_push': int(row[4]), 'f': row[5]} for row in reader}

with open('quickjs/quickjs-atom.h') as f:
    for line in f:
        line = line.strip()
        if line.startswith('DEF('):
            name = line[4:].split(',')[1].split('"')[1]
            default_atoms.append(name)

def bytes_from_int(value, n):
    bytes = []
    for i in range(n):
        bytes.append(value & 0xFF)
        value >>= 8
    return bytes

def parse_int(value):
    if value.startswith('0x'):
        return int(value, 16)
    elif value.startswith('0b'):
        return int(value, 2)
    elif value.startswith('0o'):
        return int(value, 8)
    else:
        return int(value)

def update_stack_tracker(stack_tracker, op):
    stack_tracker['size'] += op['n_push'] - op['n_pop']
    if stack_tracker['size'] > stack_tracker['max_size']:
        stack_tracker['max_size'] = stack_tracker['size']
    if stack_tracker['size'] < 0:
        raise Exception(f'Stack underflow')

def parse_instruction(line, stack_tracker, local_vars, constants, property_overrides):
    parts = shlex.split(line.strip())
    
    if len(parts) == 0 or parts[0].startswith('#'):
        return []
    
    if parts[0].startswith(':'):
        if not len(parts) == 2:
            raise Exception(f'Invalid property override {parts[0]}')

        prop_name = parts[0][1:]
        if prop_name in property_overrides:
            raise Exception(f'Property {prop_name} already defined')
        prop_value = parts[1]
        property_overrides[prop_name] = prop_value
        return []

    if parts[0].startswith('$'):
        if not len(parts) == 3:
            raise Exception(f'Invalid local variable definition {parts[0]}')

        var_name = parts[0][1:]
        if var_name in local_vars:
            raise Exception(f'Local variable {var_name} already defined')
        scope_level = int(parts[1])
        next_scope_level = int(parts[2])
        local_vars[var_name] = [scope_level, next_scope_level, 0, len(local_vars)]
        return []
    elif parts[0].startswith('@'):
        if not len(parts) == 2:
            raise Exception(f'Invalid constant definition {parts[0]}')

        const_name = parts[0][1:]
        if const_name in constants:
            raise Exception(f'Constant {const_name} already defined')
        const_value = parts[1]

        if const_value.startswith('<') and const_value.endswith('>'):
            included_filepath = const_value[1:-1]
            function_bytes = assemble_file(included_filepath, const_name, False)
            constants[const_name] = [12, function_bytes, len(constants)]
        elif '.' in const_value:
            if const_value.startswith('f.'):
                float_bytes = int(const_value[2:], 16)
                constants[const_name] = [6, float_bytes, len(constants)]
            else:
                constants[const_name] = [6, int(np.float64(const_value).view(np.int64)), len(constants)]
        elif const_value == '*':
            constants[const_name] = [12, FLOAT_ADD_RAW_BC, len(constants)]
        else:
            constants[const_name] = [0, parse_int(const_value), len(constants)]
        return []
    
    op = opcodes.get(parts[0].lower())
    if op is None:
        raise Exception(f'Opcode {parts[0]} not found')
    
    if op['size'] == 1:
        if len(parts) != 1:
            raise Exception(f'Opcode {parts[0]} expects no arguments')
        
        update_stack_tracker(stack_tracker, op)

        return [op['code']]
    
    else:
        if len(parts) != 2:
            raise Exception(f'Opcode {parts[0]} expects one argument')

        operand_size = op['size'] - 1
        if parts[1][0].isdigit() or parts[1][0] == '-':
            operand = parse_int(parts[1])
        elif op['f'] == 'atom':
            if parts[1] in atoms:
                operand = atoms.index(parts[1])
            else:
                operand = new_atom(parts[1])
        elif op['f'] == 'loc':
            if parts[1] in local_vars:
                operand = local_vars[parts[1]][3]
            else:
                raise Exception(f'Local variable {parts[1]} not found')
        elif op['f'] == 'const8':
            if parts[1] in constants:
                operand = constants[parts[1]][2]
            else:
                raise Exception(f'Constant {parts[1]} not found')
        else:
            raise Exception(f'Invalid operand {parts[1]} for opcode {parts[0]}')

        update_stack_tracker(stack_tracker, op)

        return [op['code']] + bytes_from_int(operand, operand_size)

def new_atom(value):
    custom_atoms.append(value)
    atoms.append(value)
    return len(atoms) - 1

def assemble_file(filepath, func_name, is_root):
    stack_tracker = {"size": 0, "max_size": 0}
    local_vars = {'<ret>': [0, 0, 0, 0]}
    constants = {}
    property_overrides = {}

    if func_name not in atoms:
        new_atom(func_name)

    exec_bytecode = []
    with open(filepath) as f:
        for i, line in enumerate(f):
            try:
                instruction = parse_instruction(line, stack_tracker, local_vars, constants, property_overrides)
                exec_bytecode.extend(instruction)
            except Exception as e:
                print(f'Error parsing line {i + 1}: {e}')
                exit(1)

    for var_name in local_vars.keys():
        new_atom(var_name)

    filename_atom = new_atom(filepath)

    bc = BytecodeWriter()

    def write_atom_ref(atom):
        bc.write_leb128(atoms.index(atom) << 1)

    if is_root:
        # Write header
        bc.write_u8(0x43)  # Version
        bc.write_leb128(len(custom_atoms)) # Custom atom count

        # Write atoms
        for custom_atom in custom_atoms:
            bc.write_leb128(len(custom_atom) << 1) # Atom length
            bc.write_string(custom_atom, False)

        bc.write_u8(12) # Tag
    
    bc.write_u16(0b00000110_00000000) # Flags
    bc.write_u8(0) # Mode
    write_atom_ref(func_name) # Function name
    bc.write_leb128(0) # Argument count
    bc.write_leb128(len(local_vars)) # Variable count
    bc.write_leb128(0) # Defined argument count
    bc.write_leb128(int(property_overrides['stack_size']) if 'stack_size' in property_overrides else stack_tracker['max_size']) # Stack size
    bc.write_leb128(0) # Closure variable count
    bc.write_leb128(len(constants)) # Constant pool count
    bc.write_leb128(len(exec_bytecode)) # Bytecode length
    bc.write_leb128(len(local_vars)) # Locals count

    for loc_name, loc_data in sorted(local_vars.items(), key=lambda x: x[1][3]):
        write_atom_ref(loc_name) # Vardef name
        bc.write_leb128(loc_data[0]) # Scope level
        bc.write_leb128(loc_data[1]) # Next scope level
        bc.write_u8(loc_data[2]) # Vardef flags

    bc.write(exec_bytecode) # Instructions

    # Debug information
    bc.write_leb128(filename_atom << 1) # File name atom
    bc.write_leb128(1) # Line number
    bc.write_leb128(0) # pc2line buffer length

    # Constants
    for const_name, const_data in sorted(constants.items(), key=lambda x: x[1][2]):
        bc.write_u8(const_data[0]) # Tag

        if const_data[0] == 12: # Function bytecode
            bc.write(const_data[1])
        else:
            bc.write_u64(const_data[1]) # Value

    return bc.bytecode

if len(sys.argv) != 2 and len(sys.argv) != 3:
    print('Usage: python assembler.py <instructions_file>')
    exit(1)

custom_atoms = []
atoms = default_atoms + custom_atoms

# Add atoms used by float_add_raw
for a in ['float_add_raw', 'flt', 'val', 'view', 'setFloat64', 'getUint32', 'setUint32', 'getFloat64']:
    new_atom(a)

bc = assemble_file(sys.argv[1], '<eval>', True)

if len(sys.argv) == 2:
    with open('.asm.js', 'wb') as f:
        f.write('loadall((new Uint8Array(['.encode())
        f.write(','.join([str(b) for b in bc]).encode())
        f.write('])).buffer);'.encode())

    os.system('./chall .asm.js')
else:
    with open(sys.argv[2], 'wb') as f:
        f.write(bytes(bc))