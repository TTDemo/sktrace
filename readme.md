## sktrace
簡化一下原項目sktrace, 


## skstrace.py
python3 sktrace.py  -m spawn   -l libtiny.so  -i 0xD9390  -s 0x100  com.xingin.xhs
python3 sktrace.py  -m attach  -l libtiny.so  -i 0xD9390  -s 0x100  小红书

輸出3個文件
*_raw_ins.log
*_tiny_ins.log
*_patch.log

## patch_batch_plugin.py
根據 *_patch.log 內容對對ida 進行patch



## 參考
https://github.com/lasting-yang/frida-qbdi-tracer

https://github.com/bmax121/sktrace