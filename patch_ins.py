import re
import idc
import keystone 
ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

file_path = 'C:\\Users\\t\\Desktop\\sktrace\\trace_ins.log'


recent_ins_list = []

def find_bl_address(recent_ins_list, reg):
    last_inses = recent_ins_list[::-1]
    for instruction_line in last_inses:
        pattern = re.compile(r'%s:0x[0-9A-Fa-f]+!0x[0-9A-Fa-f]+'%reg)
        # 使用正则表达式进行匹配
        match = pattern.search(instruction_line)
        if match:
            to_addr = match.group().split("!")[1]
            return to_addr
    
    return None


def patch_ins(offet, ins):
    print("offset:%s patch ins:%s"%(hex(offset), ins))
    # encoding, count = ks.asm(ins, offet)
    # if count :
    #     for i in range(4):
    #         idc.patch_byte(offset + i, encoding[i])


# 打开文件并按行读取
with open(file_path, 'r') as file:
    for line in file:
        # 如果是跳转指令
        if "blr" in line:
            instruction_line = line.strip()
            tokens = instruction_line.split()
            offset = int(tokens[0], 16)
            reg  = tokens[2]
            bl_addr = find_bl_address(recent_ins_list, reg)
            if bl_addr != None:  
                ins = "bl " + bl_addr
                patch_ins(offset, ins)
               

            recent_ins_list.clear()   
        else:
            recent_ins_list.append(line.strip())


