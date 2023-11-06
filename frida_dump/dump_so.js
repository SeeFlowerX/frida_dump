function log(message) {
    send({"log": message});
}

function hook_dlopen(target_so, symbol) {
    let libdl = Process.getModuleByName("libdl.so")
    Interceptor.attach(libdl.getExportByName(symbol),{
        onEnter: function(args) {
            this.libname = args[0].readCString();
            log(`[${symbol}] ${this.libname} pid:${Process.id} tid:${Process.getCurrentThreadId()}`);
            this.hook = false;
            if (this.libname.includes(target_so)) {
                this.hook = true;
            }
        },
        onLeave: function(retval) {
            log(`[${symbol}] handle:${retval}`);
            if(this.hook) {
                dump_so(target_so);
            };
        }
    });
    log(`[${symbol}] hook end`);
}

function dump_so(target_so) {
    log(`[dump_so] ${JSON.stringify(Process.findModuleByName("libc.so"))}`);
    let libso = Process.findModuleByName(target_so);
    if (libso == null) {
        log(`[dump_so] findModuleByName for ${target_so} failed!`);
        return;
    }
    log(`[dump_so] ${JSON.stringify(libso)}`);
    Memory.protect(ptr(libso.base), libso.size, 'rwx');
    let buffer = ptr(libso.base).readByteArray(libso.size);
    send({"type": "buffer", "arch": Process.arch, "base": libso.base, "size": libso.size}, buffer);
    log(`[dump_so] for ${target_so} end!`);
}

function main(target_so) {
    hook_dlopen(target_so, "dlopen");
    hook_dlopen(target_so, "android_dlopen_ext");
}

rpc.exports = {
    main: main,
    dumpso: dump_so,
}