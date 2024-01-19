
"""
A instruction trace script based on Frida-Stalker.
"""

import argparse
import binascii
import json
import os
import frida

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


f = open("trace.log", 'w') 
inst_dict = {}
base_addr = 0

class Inst:
    def __init__(self, base, inst):
        self.base = base
        self.addr = inst["address"]
        self.inst = inst

    
    def trace_ins(self, ctx):
        offet = hex(int(self.addr, 16)-int(self.base, 16)).upper()
        
        regs = []
        for operand  in self.inst["operands"] :
            if operand["type"] == "reg" and operand["value"] not in regs:
                regs.append(operand["value"])
        regs_str = ""
        for reg in regs:
            if reg in ctx.ctx:
                regs_str += ("{}:{}  ".format(reg, ctx.ctx[reg]))
        inst_line = "{}!{:<10}{:<15}{:<30}{}".format(self.addr.upper(), offet, self.inst["mnemonic"], self.inst["opStr"], regs_str)
        trace_log(inst_line)


class Arm64Ctx:
        def __init__(self, ctx):
          self.pc = ctx["pc"]
          self.ctx = ctx



def trace_log(obj):
    print(str(obj))
    f.write(str(obj) + "\n")
    f.flush()




def on_message(msg, data):
    if msg['type'] == 'error':
        trace_log(msg)
        return

    if msg['type'] == 'send':
        payload = msg['payload']
        # tid = payload['tid']
        type = payload['type']
        if type == 'enter':
            # val = json.loads(payload['val'])
            # base = int(val["base"], 16)
            pass
        elif type == 'inst':
            val = json.loads(payload['val'])
            inst = Inst(payload["base"], val)
           
            # trace_log(inst.simple_str())
            inst_dict[inst.addr] = inst
        elif type == 'ctx':
            # print(payload)
            val = json.loads(payload['val'])            
            ctx = Arm64Ctx(val)
            if ctx.pc not in inst_dict:
                raise Exception("No inst addr:{} maybe caused by Interceptor.payload:{}".format(ctx.pc, payload))
        
            inst_dict[ctx.pc].trace_ins(ctx)
            # self.inst_dict[ctx.pc].cal_regs_change(self.pre_ctx, ctx)
            pass
        elif type == "leave":
            # print(payload)
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

    # _finish(args, device, pid, scripts)

if __name__ == '__main__':
    main()





