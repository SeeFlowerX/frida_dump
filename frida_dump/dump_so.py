import os
import re
import sys
import time
import signal
import logging
import subprocess
from pathlib import Path
from argparse import ArgumentParser

from frida_dump.cmd import CmdArgs
from frida_dump.log import setup_logger

__version__ = '1.0.0'
project_name = 'frida_dump'
logger = setup_logger('frida_dump', level='DEBUG')

def use_sofixer(arch: str, save_name: str, so_name: str, base: str):
    exe_path = "/data/local/tmp/SoFixer"
    dump_path = "/data/local/tmp/" + so_name
    fix_path = os.path.splitext(dump_path)[0] + "_fix.so"
    if arch == "arm":
        os.system("adb push android/SoFixer32 " + exe_path)
    elif arch == "arm64":
        os.system("adb push android/SoFixer64 " + exe_path)
    os.system("adb shell chmod +x " + exe_path)
    os.system("adb push " + so_name + " " + dump_path)
    print("adb shell " + exe_path + " -m " + base + " -s " + dump_path + " -o " + fix_path)
    os.system("adb shell " + exe_path + " -m " + base + " -s " + dump_path + " -o " + fix_path)
    os.system("adb pull " + fix_path + " " + save_name)
    os.system("adb shell rm " + dump_path)
    os.system("adb shell rm " + fix_path)
    os.system("adb shell rm " + exe_path)

    return save_name

def use_fixso(arch: str, save_name: str, so_name: str, base: str):
    exe_path = "/data/local/tmp/fixso"
    dump_path = "/data/local/tmp/" + so_name
    fix_path = os.path.splitext(dump_path)[0] + "_fix.so"
    if arch == "arm":
        os.system("adb push android/fixso32 " + exe_path)
    elif arch == "arm64":
        os.system("adb push android/fixso64 " + exe_path)
    os.system("adb shell chmod +x " + exe_path)
    os.system("adb push " + so_name + " " + dump_path)
    print("adb shell " + exe_path + " " + dump_path + " " + base + " " + fix_path)
    os.system("adb shell " + exe_path + " " + dump_path + " " + base + " " + fix_path)
    os.system("adb pull " + fix_path + " " + save_name)
    os.system("adb shell rm " + dump_path)
    os.system("adb shell rm " + fix_path)
    os.system("adb shell rm " + exe_path)

    return save_name

def on_detached(reason, *args):
    sys.exit(f'rpc detached, reason:{reason} args:{args}, go exit')

def on_message(message: dict, data: bytes, base_name: str, sofixer: bool):
    # print(f'recv message -> {message}')
    if message['type'] == 'send':
        if message['payload'].get('log'):
            logger.info(message['payload']['log'])
        elif message['payload'].get('type') == 'buffer':
            logger.info('buffer recv')
            dump_so = base_name + "_dump.so"
            Path(dump_so).write_bytes(data)
            arch = message['payload']["arch"]
            base = message['payload']["base"]
            size = message['payload']["size"]
            save_name = base_name + "_" + base + "_" + str(size) + "_fix.so"
            if sofixer:
                fix_so_name = use_sofixer(arch, save_name, dump_so, base)
            else:
                fix_so_name = use_fixso(arch, save_name, dump_so, base)
            logger.info(fix_so_name)
        else:
            logger.debug(message['payload'])


def handle_exit(signum, frame, script: 'frida.core.Script'):
    script.unload()
    sys.exit('hit handle_exit, go exit')

def run_cmd(cmd: str, show_cmd: bool = False):
    if show_cmd:
        print('[*] run_cmd:', cmd)
    output = subprocess.check_output(['adb', 'shell', cmd], shell=False)
    return output.decode('utf-8')


def shell_dump(args: CmdArgs):
    result = run_cmd('readelf -s /system/bin/linker64 | grep __dl__ZL6solist')
    solist_offset = int(result.strip().split(' ')[1], base=16)
    
    result = run_cmd(f'pidof {args.attach_name}')
    target_pid = result.strip()

    os.system(f'adb shell su -c "kill -SIGSTOP {target_pid}"')
    
    result = run_cmd(f'su -c "cat /proc/{target_pid}/maps | grep linker64"')
    result_str = result.strip().splitlines()[0].split('-')[0]
    linker_base = int(result_str, base=16)
    
    result = run_cmd(f'su -c "cat /proc/{target_pid}/maps | grep {args.TARGET[0]}"')
    result_lines = result.strip().splitlines()
    target_base = None
    target_end = None
    for index, line in enumerate(result_lines):
        base_end = line.split(' ')[0]
        if index == 0:
            target_base = int(base_end.split('-')[0], base=16)
        if index == len(result_lines) - 1:
            target_end = int(base_end.split('-')[1], base=16)
    if target_base is None:
        sys.exit('can not get target base')
    if target_end is None:
        sys.exit('can not get target end')
    target_size = target_end - target_base

    solist_addr = linker_base + solist_offset

    print(f'[+] solist:{solist_addr:#x} target:{target_base:#x}')

    result = run_cmd(f'su -c "xxd -p -l 8 -s {solist_addr:#x} /proc/{target_pid}/mem"')
    solist_head = int.from_bytes(bytes.fromhex(result), byteorder='little')
    print(f'[*] solist head:{solist_head:#x}')

    ptr_size = 8
    off_base = 0x10
    off_size = 0x18
    off_next = 0x28

    result = run_cmd(f'su -c "xxd -p -l 256 -s {solist_head:#x} /proc/{target_pid}/mem"')
    soinfo_raw = bytes.fromhex(result)
    soinfo_base = int.from_bytes(soinfo_raw[off_base:off_base + ptr_size], byteorder='little')
    soinfo_next = int.from_bytes(soinfo_raw[off_next:off_next + ptr_size], byteorder='little')
    print(f'[*] first soinfo base:{soinfo_base:#x} next:{soinfo_next:#x}')

    result = run_cmd(f'su -c "dd if=/proc/{target_pid}/mem of=/data/local/tmp/soinfo iflag=skip_bytes skip={soinfo_next:#x} bs=1K count={256}"')
    # print('[+] dd result:', result)

    os.system('adb pull /data/local/tmp/soinfo')
    os.system('adb shell su -c "rm /data/local/tmp/soinfo"')

    target_pattern = target_base.to_bytes(8, byteorder='little')
    soinfo_path = Path('soinfo')
    soinfo_raw = soinfo_path.read_bytes()
    soinfo_size = 0
    for item in re.finditer(target_pattern, soinfo_raw):
        offset = item.start() + ptr_size
        soinfo_size = int.from_bytes(soinfo_raw[offset:offset + ptr_size], byteorder='little')
        print('[+] soinfo_size', soinfo_size)

        if soinfo_size > target_size * 10:
            print('[*] use target_size as soinfo_size', target_size)
            soinfo_size = target_size

        # 可能有多个 一般第一个是对的
        break

    soinfo_path.unlink()

    if soinfo_size == 0:
        print('[*] use target_size as soinfo_size', target_size)
        soinfo_size = target_size

    if soinfo_size > 0:

        arch = 'arm64'
        dump_so = 'dump_so'
        base = hex(target_base)
        size = str(soinfo_size)

        result = run_cmd(f'su -c "dd if=/proc/{target_pid}/mem of=/data/local/tmp/{dump_so} iflag=skip_bytes skip={target_base:#x} bs={soinfo_size} count=1"')
        # print('[+] dd result:', result)

        os.system(f'adb pull /data/local/tmp/{dump_so}')
        os.system(f'adb shell su -c "rm /data/local/tmp/{dump_so}"')

        base_name = os.path.splitext(args.TARGET[0])[0]
        save_name = base_name + "_" + base + "_" + size + "_fix.so"
        if args.sofixer:
            fix_so_name = use_sofixer(arch, save_name, dump_so, base)
        else:
            fix_so_name = use_fixso(arch, save_name, dump_so, base)
        print(f'[+] {fix_so_name}')
    
    os.system(f'adb shell su -c "kill -SIGCONT {target_pid}"')

def main():
    # <------ 正文 ------>
    parser = ArgumentParser(
        prog='frida_dump script',
        usage='python -m frida_dump.dump_so [OPTION]...',
        description=f'version {__version__}, frida_dump server',
        add_help=False
    )
    parser.add_argument('-v', '--version', action='store_true', help='print version and exit')
    parser.add_argument('-h', '--help', action='store_true', help='print help message and exit')
    parser.add_argument('-s', '--sofixer', action='store_true', help='use SoFixer, default use fixso')
    parser.add_argument('-f', '--spawn', action='store_true', help='spawn file')
    parser.add_argument('--shell', action='store_true', help='shell mode')
    parser.add_argument('-n', '--attach-name', help='attach to NAME')
    parser.add_argument('-p', '--attach-pid', help='attach to PID')
    parser.add_argument('-H', '--host', help='connect to remote frida-server on HOST')
    parser.add_argument('--runtime', default='qjs', help='only qjs know')
    parser.add_argument('--log-level', default='DEBUG', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='set log level, default is INFO')
    parser.add_argument('TARGET', nargs='*', help='TARGET so name string')
    args = parser.parse_args() # type: CmdArgs
    if args.help:
        parser.print_help()
        sys.exit()
    if args.version:
        parser.print_help()
        sys.exit()
    assert len(args.TARGET) > 0, 'plz set target'
    if args.shell:
        return shell_dump(args)
    if args.attach_name is None and args.attach_pid is None:
        sys.exit('set NAME or PID, plz')
    if args.attach_name and args.attach_pid:
        sys.exit('set NAME or PID only one, plz')
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler) is False:
            handler.setLevel(logging.getLevelName(args.log_level))
    logger.info(f'start {project_name}, current version is {__version__}')
    target = args.attach_name
    if args.attach_pid:
        target = args.attach_pid
    try:
        import frida
        if args.host:
            device = frida.get_device_manager().add_remote_device(args.host)
        else:
            device = frida.get_usb_device(timeout=10)
        if args.spawn:
            logger.info(f'start spawn {target}')
            pid = device.spawn(target)
            session = device.attach(pid)
            device.resume(pid)
        else:
            logger.info(f'start attach {target}')
            session = device.attach(target)
    except Exception as e:
        logger.error(f'attach to {target} failed', exc_info=e)
        sys.exit()

    logger.info(f'attach {target} success, inject script now')
    try:
        jscode = Path('frida_dump/dump_so.js').read_text(encoding='utf-8')
        script = session.create_script(jscode, runtime='qjs')
        script.load()
        session.on('detached', on_detached)
        base_name = os.path.splitext(args.TARGET[0])[0]
        script.on('message', lambda message, data: on_message(message, data, base_name, args.sofixer))
    except Exception as e:
        logger.error(f'inject script failed', exc_info=e)
        sys.exit()
    rpc = script.exports
    if args.spawn:
        rpc.main(args.TARGET[0])
    else:
        rpc.dumpso(args.TARGET[0])
    # <------ 处理手动Ctrl+C退出 ------>
    signal.signal(signal.SIGINT, lambda signum, frame: handle_exit(signum, frame, script))
    signal.signal(signal.SIGTERM, lambda signum, frame: handle_exit(signum, frame, script))
    # wait
    sys.stdin.read()
 
if __name__ == '__main__':
    main()
