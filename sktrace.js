function sk_trace_range(tid, begin, end) {
    Stalker.follow(tid, {
        transform: (iterator) => {
            const instruction = iterator.next();
            const startAddress = instruction.address;
            const isModuleCode = startAddress.compare(begin) >= 0 && startAddress.compare(end) < 0;
            do {
                iterator.keep();
                if (isModuleCode) {       
                    send({
                        type: 'inst',
                        tid: tid,
                        block: startAddress,
                        val: JSON.stringify(instruction)
                    })
                    iterator.putCallout((context) => {
                            send({
                                type: 'ctx',
                                tid: tid,
                                val: JSON.stringify(context),
                            })

                    })
                }
            } while (iterator.next() !== null);
        }
    })
}

function sk_trace_range_in_module(module) {
    sk_trace_range(Process.getCurrentThreadId(),  module.base, module.base.add(module.size))
}

function sk_trace_func(module, fuc_addr, offset) {  
    send({type: "module", tid: Process.getCurrentThreadId(), val: module})
    Interceptor.attach(fuc_addr, {
        onEnter: function(args) {
            console.log(`onEnter: ${module.name} ${fuc_addr}`)
            this.tid = Process.getCurrentThreadId();
            //sk_trace_range_in_module(module)
            sk_trace_range(this.tid, fuc_addr, fuc_addr.add(offset))
        },
        onLeave: function(ret) {
            console.log(`onLeave: ${module.name} ${fuc_addr}`)
            Stalker.unfollow(this.tid);
            Stalker.garbageCollect()
            send({
                type: "leave",
                tid: this.tid
            })
            
        }
    })
}

function watch_lib_load(libname, callback) {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),{
        onEnter: function (args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                if (path.indexOf(libname) >= 0) {
                    this.load = true;
                }
            }
        },
        onLeave: function (retval) {
            if (this.load) {
                callback(Process.getModuleByName(libname));
            }
        }
    });
}

function enumerateExports(libname) {
    console.log("Enumerating exports of " + libname + "...");
    
    // 枚举并将目标模块中的所有导出函数添加到数组中
    Module.enumerateExports({
        module: "libc.so",
        onMatch: function (exp) {
            exportsArray.push(exp.name);
            console.log(exp.name);
        },
        onComplete: function () {
            console.log("Enumeration completed.");
            send({type:"exports", lib:libname, val:exportsArray});
        }
    });
}

(() => {
    recv("config", (msg) => {
        const payload = msg.payload;
        console.log(JSON.stringify(payload))
        const libname = payload.libname;
        console.log(`libname:${libname}`)
        var exportsArray = {};
        Process.enumerateModules({
            onMatch: function (module) {
                    // 枚举导出函数并打印地址
                    if (module.name.indexOf("libc.so") >= 0) {
                        Module.enumerateExports(module.name, {
                            onMatch: function (exportedFunction) {
                               //exportsArray[exportedFunction.address] =  module.name + "!"+ exportedFunction.name;
                                exportsArray[exportedFunction.address] =  exportedFunction.name;
                            },
                            onComplete: function () {
                                console.log('Export enumeration completed.');
                            }
                        });
                    }
                  
                },
            onComplete: function () {
                console.log('Module enumeration completed.');
                send({type:"exports", val:exportsArray});
            }
        });

        if(!payload.spawn) {
            const tmodule = Process.getModuleByName(libname);
            let func_address = null;
            if("symbol" in payload) {
                func_address = t_module.findExportByName(payload.symbol);
            } else if("offset" in payload) {
                func_address = t_module.base.add(ptr(payload.offset));
            }
            sk_trace_func(t_module, func_address, payload.size)
            return;
        }else { 
            watch_lib_load(libname, (t_module) => {
                let func_address = null;
                if("symbol" in payload) {
                    func_address = t_module.findExportByName(payload.symbol);
                } else if("offset" in payload) {
                    func_address = t_module.base.add(ptr(payload.offset));
                }
                sk_trace_func(t_module, func_address, payload.size)
            })
        }
    })
})()