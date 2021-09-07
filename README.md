# nds2elf

## Requirements
nds2elf.py uses LIEF and `template.elf` to form a new binary. LIEF is available via pip:
```
pip3 install lief
```

## Usage
DSi and DSi-enhanced titles currently need to be demodcrypted prior to running. This can be done with [twltool](https://github.com/WinterMute/twltool) and
```
twltool modcrypt --in sys_menu.nds --out sys_menu.dec.nds
```

Once decrypted:
```
python3 nds2elf.py sys_menu.dec.nds regs_arm7_list.txt
```

The output in this case would be `sys_menu.dec.nds.elf`.
