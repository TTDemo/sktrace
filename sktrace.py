
"""
A instruction trace script based on Frida-Stalker.
"""

import argparse
import json
import os
import frida
import re

__version__ = "1.0.0"

def _finish(args, device, pid, scripts):
    print('Stopping application (name={}, pid={})...'.format(
        args.target,
        pid
    ), end="")
    try:
        if args.append:
            scripts["append"].unload()
        scripts["script"].unload()
        if args.prepend:
            scripts["prepend"].unload()
        device.kill(pid)
    except frida.InvalidOperationError:
        pass
    finally:
        print("stopped.")


def _custom_script_on_message(message, data):
    print(message, data)


def _parse_args():
    parser = argparse.ArgumentParser(usage="sktrace [options] -l libname -i symbol|hexaddr target")
    parser.add_argument("-m", "--inject-method", choices=["spawn", "attach"],
                        default="spawn",
                        help="Specify how frida should inject into the process.")
    parser.add_argument("-l", "--libname", required=True, 
                        help="Specify a native library like libnative-lib.so")
    parser.add_argument("-i", "--interceptor", required=True, 
                        help="Specity a function (symbol or a hex offset address) to trace.")
    parser.add_argument("-s", "--size", required=True, 
                        help="Specity a trace  address size.")
    parser.add_argument("-p", "--prepend", type=argparse.FileType("r"),
                        help="Prepend a Frida script to run before sktrace does.")
    parser.add_argument("-a", "--append", type=argparse.FileType("r"),
                        help="Append a Frida script to run after sktrace has started.")
    parser.add_argument("-v", "--version", action='version',
                        version="%(prog)s " + __version__,
                        help="Show the version.")
    parser.add_argument("target",
                        help="The name of the application to trace.")
    args = parser.parse_args()

    return args


file_raw_ins    = None 
file_tiny_ins   = None
file_patch      = None
inst_dict = {}
last_trace_pc = 0

class Inst:
    def __init__(self,  inst):
        self.addr = inst["address"]
        self.inst = inst
        self.ctx = None



class Arm64Ctx:
    def __init__(self, ctx):
        self.pc = ctx["pc"]
        self.ctx = ctx



def trace_log(obj, f):
    f.write(str(obj) + "\n")
    f.flush()
    pass


def trace_ins(inst, file_ins):
    offet = hex(int(inst.addr, 16)-int(env["module"]["base"], 16)).upper()
    regs_str = ""
    if inst.ctx != None:
        regs = []
        for operand  in inst.inst["operands"] :
            if operand["type"] == "reg" and operand["value"] not in regs:
                regs.append(operand["value"])
        for reg in regs:
            if reg in inst.ctx:
                regs_str += ("{}:{}  ".format(reg, inst.ctx[reg]))
    
    jmpTag = ""
    mnemonic = inst.inst["mnemonic"]
    if mnemonic == "bl" or mnemonic == "b" or mnemonic == "blr" or mnemonic == "br":
        jmpTag = "\r\n"
        
    inst_line = "{:<15}{:<15}{:<30}{}{}".format(offet, mnemonic, inst.inst["opStr"], regs_str, jmpTag)
    trace_log(inst_line, file_ins)
    pass

def trace_call_out(inst, file):
    global last_trace_pc
    cur_pc = int(inst.ctx["pc"], 16)
    if last_trace_pc != 0:
        if cur_pc - last_trace_pc >= 8:
            trace_ins(inst_dict[str(hex(last_trace_pc+4))], file)
    trace_ins(inst, file)
    last_trace_pc = cur_pc
    pass

def trace_summery(file_smy):
    for inst in inst_dict.values():
        trace_ins(inst, file_smy)      
    pass

env = {}

def on_message(msg, data):
    if msg['type'] == 'error':
        # trace_log(msg)
        return

    if msg['type'] == 'send':
        payload = msg['payload']
        type = payload['type']
        
        if type == 'module':
            env["module"] = payload["val"]
            # trace_log(json.dumps(env), trace_env)
            pass
        elif type == 'exports':
            env["exports"] = payload["val"]
            # trace_log(json.dumps(payload), trace_env)
            pass
        elif type == 'inst':
            val = json.loads(payload['val'])
            inst = Inst(val)
            inst_dict[inst.addr] = inst
            # trace_ins(inst, file_ins)
        elif type == 'ctx':
            val = json.loads(payload['val'])            
            ctx = Arm64Ctx(val)
            if ctx.pc not in inst_dict:
                raise Exception("No inst addr:{} maybe caused by Interceptor.payload:{}".format(ctx.pc, payload))
            inst_dict[ctx.pc].ctx = ctx.ctx
            trace_call_out(inst_dict[ctx.pc], file_raw_ins)
            pass
        elif type == "leave":
            # trace_summery(file_smy)
            pass
        else:
            raise Exception("Unknown message type: {}".format(type))

recent_ins_list = []
def read_reg(recent_ins_list, reg):
    last_inses = recent_ins_list[::-1]
    for instruction_line in last_inses:
        pattern = re.compile(r'%s:0x[0-9A-Fa-f]+'%reg)
        # 使用正则表达式进行匹配
        match = pattern.search(instruction_line)
        if match:
            to_addr = match.group().split(":")[1]
            return to_addr
    
    print("read_reg error")
    return None


def tiny_ins(file_path):
    ins_file  =  open(file_path, 'r')
    for line in ins_file:
        if "blr" in line or "br" in line:
            trace_log("- "+line.strip(), file_tiny_ins)
            instruction_line = line.strip()
            # print(instruction_line)
            tokens = instruction_line.split()
            offset = int(tokens[0], 16)
            mnemonic = tokens[1]
            reg_name  = tokens[2]
            reg_val = read_reg(recent_ins_list, reg_name)

            if reg_val != None:  
                if reg_val in env["exports"]:
                    reg_val = env["exports"][reg_val]
                else:
                    reg_val = hex(int(reg_val, 16) - int(env["module"]["base"], 16))

                inst_line = "{:<15}{:<15}{:<30}".format(hex(offset).upper(), mnemonic[:-1], reg_val.upper())
                trace_log(inst_line, file_patch)
                trace_log("+ " + inst_line, file_tiny_ins)

            recent_ins_list.clear()   
        else:
            recent_ins_list.append(line)
            trace_log("+ " + line.strip(), file_tiny_ins)
        pass


def main():
    script_file = os.path.join(os.path.dirname(__file__), "sktrace.js")
    try:
        script = open(script_file, encoding='utf-8').read()
    except:
        raise Exception("Read script error.")

   

    args = _parse_args()
    config = {
        "type": "config",
        "payload": {}
    }

    config["payload"]["libname"] = args.libname

    if args.interceptor.startswith("0x") or args.interceptor.startswith("0X"):
        config["payload"]["offset"] = int(args.interceptor, 16)
    else:
        config["payload"]["symbol"] = args.interceptor

    global file_raw_ins 
    global file_tiny_ins
    global file_patch

    ins_path = "trace_ins_%s.ins"%str(args.interceptor)
    file_raw_ins  = open(ins_path, 'w') 
    file_tiny_ins = open("tiny_%s.ins"%str(args.interceptor), 'w')
    file_patch    = open("%s.patch"%str(args.interceptor), 'w')

    
    config["payload"]["size"] = int(args.size, 16)
    
    device = frida.get_remote_device()
    if args.inject_method == "spawn":
        pid = device.spawn([args.target])
        config["payload"]["spawn"] = True
    else:
        pid = device.get_process(args.target).pid
        config["payload"]["spawn"] = False

    session = device.attach(pid)
    scripts = {}

    if args.prepend:
        prepend = session.create_script(args.prepend.read())
        prepend.on("message", _custom_script_on_message)
        prepend.load()
        args.prepend.close()
        scripts["prepend"] = prepend

    script = session.create_script(script)
    script.on("message", on_message)
    script.load()
    scripts["script"] = script

    script.post(config)

    if args.append:
        append = session.create_script(args.append.read())
        append.on("message", _custom_script_on_message)
        append.load()
        args.append.close()
        scripts["append"] = append

    if args.inject_method == "spawn":
        device.resume(pid)

    print("Tracing. Press any key to quit...")

    try:
        input()
    except KeyboardInterrupt:
        pass
    file_raw_ins.close()
    tiny_ins(ins_path)
    # _finish(args, device, pid, scripts)

if __name__ == '__main__':
    main()






