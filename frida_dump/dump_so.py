import os
import sys
import frida
import signal
import logging
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
    fix_path = dump_path + "_fix.so"
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


def handle_exit(signum, frame, script: frida.core.Script):
    script.unload()
    sys.exit('hit handle_exit, go exit')

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