# 打開文件 13c844.log 
import re
import idc
import keystone as ks

file_path = '13c844.log'


recent_ins_list = []
# 打开文件并按行读取
with open(file_path, 'r') as file:
    for line in file:
        if "br" in line or "blr" in line:
            instruction_line = line.strip()
            tokens = instruction_line.split()

            last_ins = recent_ins_list[-1]
            # 定义正则表达式模式
            pattern = re.compile(r'x8:0x[0-9A-Fa-f]+!0x[0-9A-Fa-f]+')
            # 使用正则表达式进行匹配
            match = pattern.search(last_ins)
            if match:
                result = match.group().split("!")[1]
                print(tokens[0].split("!")[1] +  " " + tokens[1] +" "  + result)

                if tokens[1] == "br":
                    to_addr = result
                encoding, count = ks.asm(f'b {to_addr}', B_addr)
                if not count:
                    print('ks.asm err')
                else:
                    for i in range(4):
                        idc.patch_byte(B_addr + i, encoding[i])
            recent_ins_list.clear()
        else:
            recent_ins_list.append(line.strip())

