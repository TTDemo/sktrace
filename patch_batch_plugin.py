# patch_batch_plugin.py

import idaapi
import idc
import keystone

ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
def patch_ins(offset, ins):
    print("offset:%s patch ins:%s"%(hex(offset), ins))
    encoding, count = ks.asm(ins, offset)
    if count:
        for i in range(4):
            idc.patch_byte(offset + i, encoding[i])

class BatchPatchPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Patch Instructions Based on Text"
    help = "This plugin path instructions based on text"
    wanted_name = "BatchPatchPlugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        print("PatchFilePlugin initialized")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        text = idaapi.ask_text(0, "Enter some text", "Input Dialog")
        for line in text.splitlines():
            instruction_line = line.strip()
            tokens = instruction_line.split()
            offset = int(tokens[0], 16)
            idc.set_color(offset, idc.CIC_ITEM, 0x00ff00)
            ins = tokens[1] + " " + tokens[2]
            print("offset:%s patch ins:%s"%(hex(offset), ins))
            patch_ins(offset, ins)

    def term(self):
        print("PatchFilePlugin terminated")

# 注册插件
def PLUGIN_ENTRY():
    return BatchPatchPlugin()

