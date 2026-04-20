
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import z3
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP, X86_REG_RSP
from elftools.elf.elffile import ELFFile

THREE_SAT_BUF = 0x15060
INPUT_LEN = 1279

SAT_FUNC_START = 0x1289
SAT_FUNC_END = 0x12982


def low8(register: str) -> str:
    # only use low 8-bit view with Capstone
    register = register.lower()
    mapping = {
        "al": "al",
        "eax": "al",
        "rax": "al",
        "bl": "bl",
        "ebx": "bl",
        "rbx": "bl",
        "cl": "cl",
        "ecx": "cl",
        "rcx": "cl",
        "dl": "dl",
        "edx": "dl",
        "rdx": "dl",
        "sil": "sil",
        "esi": "sil",
        "rsi": "sil",
        "dil": "dil",
        "edi": "dil",
        "rdi": "dil",
        "bpl": "bpl",
        "ebp": "bpl",
        "rbp": "bpl",
        "spl": "spl",
        "esp": "spl",
        "rsp": "spl",
    }
    if register in mapping:
        return mapping[register]
    for i in range(8, 16):
        if register in {f"r{i}b", f"r{i}d", f"r{i}"}:
            return f"r{i}b"
    return register

@dataclass
class MemRef:
    kind: str
    key: int

# Encode ASCII input as 0x30 ('0') + 0 or 1
def process_ascii_bit(bit1: z3.BitVecRef) -> z3.BitVecRef:
    return z3.BitVecVal(0x30, 8) + z3.ZeroExt(7, bit1)

# Parse instructions dealing with input buffer or memory array (mov, and or, xor)
def parse_arr_instr(insn_addr: int, insn_size: int, mem) -> MemRef:
    base = mem.base
    if base == X86_REG_RIP: # part of buffer
        abs_addr = insn_addr + insn_size + mem.disp
        if not (THREE_SAT_BUF <= abs_addr < THREE_SAT_BUF + INPUT_LEN):
            raise RuntimeError(f"Buffer access in unexpected location")
        return MemRef("buffer", abs_addr)
    if base == X86_REG_RSP: # on stack
        return MemRef("stack", mem.disp)
    raise RuntimeError(f"unexpected mem base reg: {base}")

# Symbolic execution of 3sat_func
def build_return_al(path: Path) -> Tuple[z3.BitVecRef, List[z3.BitVecRef]]:
    # Read the instruction bytes from .text
    with path.open("rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        if text is None:
            raise RuntimeError("No .text section found")
        text_addr = text["sh_addr"]
        text_off = text["sh_offset"]
        if not (text_addr <= SAT_FUNC_START < text_addr + text["sh_size"]):
            raise RuntimeError("address not in .text")
        start_off = text_off + (SAT_FUNC_START - text_addr)
        f.seek(start_off)
        code = f.read(SAT_FUNC_END - SAT_FUNC_START)

    capstone = Cs(CS_ARCH_X86, CS_MODE_64) # initialize Capstone
    capstone.detail = True

    # Create bit vector to fill in SAT solution
    bits = [z3.BitVec(f"b{i}", 1) for i in range(INPUT_LEN)]

    registers: Dict[str, z3.BitVecRef] = {}
    stack: Dict[int, z3.BitVecRef] = {}
    stack_written = set()

    def reg8(reg_id: int) -> str:
        name = capstone.reg_name(reg_id)
        c = low8(name)
        if c == "rip":
            raise RuntimeError("rip used as value reg")
        return c

    def get_register(name: str) -> z3.BitVecRef:
        return registers.get(name, z3.BitVecVal(0, 8))

    def set_reg(name: str, value: z3.BitVecRef) -> None:
        registers[name] = z3.simplify(value)

    def load_mem(mr: MemRef) -> z3.BitVecRef:
        if mr.kind == "buffer":
            # Read and process bit
            idx = mr.key - THREE_SAT_BUF
            return process_ascii_bit(bits[idx])
        if mr.kind == "stack":
            if mr.key not in stack_written:
                raise RuntimeError(f"Uninitialized stack read at {mr.key:+#x}")
            return stack[mr.key]
        raise AssertionError(mr)

    def store_mem(mr: MemRef, v: z3.BitVecRef) -> None:
        stack[mr.key] = z3.simplify(v)
        stack_written.add(mr.key)

    def op_val(operand) -> z3.BitVecRef:
        if operand.type == X86_OP_IMM:
            return z3.BitVecVal(operand.imm & 0xFF, 8)
        if operand.type == X86_OP_REG:
            return get_register(reg8(operand.reg))
        if operand.type == X86_OP_MEM:
            return load_mem(parse_arr_instr(instruction.address, instruction.size, operand.mem))
        raise RuntimeError(f"Can't process operand")

    for instruction in capstone.disasm(code, SAT_FUNC_START):
        mnemonic = instruction.mnemonic
        operations = instruction.operands

        # Bypass function prologue
        if mnemonic in {"push", "pop", "sub", "add", "ret"}:
            continue

        if mnemonic == "mov":
            dest, src = operations
            v = op_val(src)
            if dest.type == X86_OP_REG:
                set_reg(reg8(dest.reg), v)
            elif dest.type == X86_OP_MEM:
                store_mem(parse_arr_instr(instruction.address, instruction.size, dest.mem), v)
            else:
                raise RuntimeError("Unsupported destination")
            continue

        elif mnemonic in {"and", "or", "xor"}:
            if len(operations) != 2 or operations[0].type != X86_OP_REG:
                raise RuntimeError(f"Instruction not supported")
            dest_name = reg8(operations[0].reg)
            a = get_register(dest_name)
            b = op_val(operations[1])
            
            if mnemonic == "and":
                out = a & b
            elif mnemonic == "or":
                out = a | b
            else:
                out = a ^ b
            set_reg(dest_name, out)
            continue

        if mnemonic == "not":
            assert len(operations) == 1 and operations[0].type == X86_OP_REG
            dest_name = reg8(operations[0].reg)
            set_reg(dest_name, ~get_register(dest_name))
            continue

    return get_register("al"), bits

def solve_assignment(path: Path) -> None:
    al, bits = build_return_al(path)
    s = z3.Solver()
    s.add(bits[754] == z3.BitVecVal(1, 1)) # satisfy extra cond from check
    s.add(al != z3.BitVecVal(0, 8)) # constrain solver to assignments that return nonzero

    if s.check() != z3.sat:
        raise RuntimeError("Unsatisfiable")
    m = s.model()

    #out = []
    f = open("out.txt", "wb")
    for b in bits:
        if m.eval(b, model_completion=True).as_long() & 1:
            f.write(b"1")
        else:
            f.write(b"0")
    print("Wrote binary to out.txt")


def main() -> None:
    bin_path = Path(__file__).with_name("three_sat_problem")
    solve_assignment(bin_path)


if __name__ == "__main__":
    main()