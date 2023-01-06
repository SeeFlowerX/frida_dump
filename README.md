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

# Thanks

[https://github.com/F8LEFT/SoFixer](https://github.com/F8LEFT/SoFixer)