# frida_dump

支持spawn模式，毕竟不是什么时候都能attach

# Usage

1. spawn模式

```bash
python -m frida_dump.dump_so --spawn -n com.hunantv.imgo.activity libexec.so
```

2. attach模式

```bash
python -m frida_dump.dump_so -n 微信 libwechatcommon.so
```

小姿势：frida 15起attach模式应当使用`frida-ps -U`看到的名字，而不是APP包名

3. 不注入dump模式

暂时仅支持64位，需要root，不需要frida

实现逻辑：

- 向目标进程发送SIGSTOP将其挂起
- 读取目标进程的maps获取到基址
- 获取linker基址，计算第一个solist的地址
- 读取soinfo链表的内存块
- 检查base是否和目标so匹配，不匹配读取下一个soinfo，直到获取到so的大小
- dump后使用elf-dump-fix修复
- 向目标进程发送SIGCONT恢复运行

```bash
python -m frida_dump.dump_so --shell -n com.coolapk.market libjiagu_64.so
```

# Thanks

- [SoFixer](https://github.com/F8LEFT/SoFixer)
- [elf-dump-fix](https://github.com/maiyao1988/elf-dump-fix)