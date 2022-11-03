import struct
import idc, idautils, ida_name
import idaapi
import ida_bytes
import ida_ua
from consts import non_sparse_consts, sparse_consts, operand_consts

encryption_with_custom_function = []

if 'g_fc_prefix_cmt' not in globals():
    g_fc_prefix_cmt = "FC: "
if 'g_fc_prefix_var' not in globals():
    g_fc_prefix_var = "FC_"

if idc.BADADDR == 0xFFFFFFFF:
    digits = 8
else:
    digits = 16

def convert_to_byte_array(const):
    byte_array = []
    if const["size"] == "B":
        byte_array = const["array"]
    elif const["size"] == "L":
        for val in const["array"]:
            byte_array += list(map(lambda x:x if type(x) == int else ord(x), struct.pack("<L", val)))
    elif const["size"] == "Q":
        for val in const["array"]:
            byte_array += list(map(lambda x:x if type(x) == int else ord(x), struct.pack("<Q", val)))
    return byte_array

def main():
    print("[*] loading crypto constants")
    for const in non_sparse_consts:
        const["byte_array"] = convert_to_byte_array(const)

    for start in idautils.Segments():
        print("[*] searching for crypto constants in %s" % idc.get_segm_name(start))
        ea = start
        while ea < idc.get_segm_end(start):
            bbbb = list(struct.unpack("BBBB", idc.get_bytes(ea, 4)))
            for const in non_sparse_consts:
                if bbbb != const["byte_array"][:4]:
                    continue
                if list(map(lambda x:x if type(x) == int else ord(x), idc.get_bytes(ea, len(const["byte_array"])))) == const["byte_array"]:
                    print(("0x%0" + str(digits) + "X: found const array %s (used in %s)") % (ea, const["name"], const["algorithm"]))
                    encryption_with_custom_function.append(1)
                    idc.set_name(ea, g_fc_prefix_var + const["name"], ida_name.SN_FORCE)
                    if const["size"] == "B":
                        ida_bytes.del_items(ea, 0, len(const["array"]))
                        idc.create_byte(ea)
                    elif const["size"] == "L":
                        ida_bytes.del_items(ea, 0, len(const["array"])*4)
                        idc.create_dword(ea)
                    elif const["size"] == "Q":
                        ida_bytes.del_items(ea, 0, len(const["array"])*8)
                        idc.create_qword(ea)
                    idc.make_array(ea, len(const["array"]))
                    ea += len(const["byte_array"]) - 4
                    break
            ea += 4

        ea = start
        if idc.get_segm_attr(ea, idc.SEGATTR_TYPE) == idc.SEG_CODE:
            while ea < idc.get_segm_end(start):
                d = ida_bytes.get_dword(ea)
                for const in sparse_consts:
                    if d != const["array"][0]:
                        continue
                    tmp = ea + 4
                    for val in const["array"][1:]:
                        for i in range(8):
                            if ida_bytes.get_dword(tmp + i) == val:
                                tmp = tmp + i + 4
                                break
                        else:
                            break
                    else:
                        print(("0x%0" + str(digits) + "X: found sparse constants for %s") % (ea, const["algorithm"]))
                        encryption_with_custom_function.append(1)
                        cmt = idc.get_cmt(idc.prev_head(ea), 0)
                        if cmt:
                            idc.set_cmt(idc.prev_head(ea), cmt + ' ' + g_fc_prefix_cmt + const["name"], 0)
                        else:
                            idc.set_cmt(idc.prev_head(ea), g_fc_prefix_cmt + const["name"], 0)
                        ea = tmp
                        break
                ea += 1

    print("[*] searching for crypto constants in immediate operand")
    funcs = idautils.Functions()
    for f in funcs:
        flags = idc.get_func_flags(f)
        if (not flags & (idc.FUNC_LIB | idc.FUNC_THUNK)):
            ea = f
            f_end = idc.get_func_attr(f, idc.FUNCATTR_END)
            while (ea < f_end):
                imm_operands = []
                insn = ida_ua.insn_t()
                ida_ua.decode_insn(insn, ea)
                for i in range(len(insn.ops)):
                    if insn.ops[i].type == ida_ua.o_void:
                        break
                    if insn.ops[i].type == ida_ua.o_imm:
                        imm_operands.append(insn.ops[i].value)
                if len(imm_operands) == 0:
                    ea = idc.find_code(ea, idc.SEARCH_DOWN)
                    continue
                for const in operand_consts:
                    if const["value"] in imm_operands:
                        print(("0x%0" + str(digits) + "X: found immediate operand constants for %s") % (ea, const["algorithm"]))
                        encryption_with_custom_function.append(1)
                        cmt = idc.get_cmt(ea, 0)
                        if cmt:
                            idc.set_cmt(ea, cmt + ' ' + g_fc_prefix_cmt + const["name"], 0)
                        else:
                            idc.set_cmt(ea, g_fc_prefix_cmt + const["name"], 0)
                        break
                ea = idc.find_code(ea, idc.SEARCH_DOWN)
    print("[*] finished")

if __name__ == '__main__':
    main()

idaapi.auto_wait()

dynamic_import = []
segment = []

for func in idautils.Functions():
    flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        continue
    dism_addr = list(idautils.FuncItems(func))
    for line in dism_addr:
        m = idc.print_insn_mnem(line)
        if m == 'call' or m == 'jmp':
            op = idc.get_operand_type(line, 0)
            if op == o_reg:
                print("0x%x %s" % (line, idc.generate_disasm_line(line, 0)))
                dynamic_import.append([line, idc.generate_disasm_line(line, 0)])

for seg in idautils.Segments():
    segs = idaapi.getseg(seg)
    segment.append(idc.SegName(seg))
    segment.append(str(segs.perm))

custom_funtion = open("output_encryption_using_custom_function.txt", 'w')
custom_funtion.write(str(encryption_with_custom_function))
custom_funtion.close()

output_runtime_api = open("output_runtime_call.txt", 'w')
output_runtime_api.write(str(dynamic_import))
output_runtime_api.close()

output_segment = open("output_segment.txt", 'w')
output_segment.write(str(segment))
output_segment.close()

idc.qexit(0)
