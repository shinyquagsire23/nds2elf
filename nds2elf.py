#!/usr/bin/python3
import lief
import sys
from lief import ELF
from nds_header import NDSHeader
import csv

sections_to_remove = [".init", ".text", ".fini", ".rodata", 
                      ".init_array", ".fini_array", ".ctors", 
                      ".dtors", ".eh_frame", ".gcc_except_table", 
                      ".data", ".init_array.00000", ".bss", ".comment", 
                      ".ARM.attributes", ".debug_frame", ".ARM.exidx",
                      ".rel.dyn", ".hash", ".got", ".plt", ".dynsym"
                      ".shstrtab"]

def make_dynamic():
    seg = ELF.Segment()
    seg.alignment = 0x4
    seg.content = []
    seg.add(ELF.SEGMENT_FLAGS.R)
    seg.add(ELF.SEGMENT_FLAGS.W)
    seg.add(ELF.SEGMENT_FLAGS.X)
    seg.type = ELF.SEGMENT_TYPES.DYNAMIC
    seg.physical_address = 0
    seg.virtual_address = 0
    seg.physical_size = 0
    seg.virtual_size = 0
    return seg

def make_load(data, addr):
    seg = ELF.Segment()
    seg.alignment = 0x4
    seg.content = list(data)
    seg.add(ELF.SEGMENT_FLAGS.R)
    seg.add(ELF.SEGMENT_FLAGS.W)
    seg.add(ELF.SEGMENT_FLAGS.X)
    seg.type = ELF.SEGMENT_TYPES.LOAD
    seg.physical_address = addr
    seg.virtual_address = addr
    seg.physical_size = len(data)
    seg.virtual_size = len(data)
    return seg

def make_memory(addr, size):
    seg = ELF.Segment()
    seg.alignment = 0x4
    seg.content = []
    seg.add(ELF.SEGMENT_FLAGS.R)
    seg.add(ELF.SEGMENT_FLAGS.W)
    seg.add(ELF.SEGMENT_FLAGS.X)
    seg.type = ELF.SEGMENT_TYPES.LOAD
    seg.physical_address = addr
    seg.virtual_address = addr
    seg.physical_size = 0
    seg.virtual_size = size
    return seg

if len(sys.argv) < 2:
    print("Usage: nds2elf.py <file.nds> [regs_arm7_list.txt]")
    sys.exit(1)

nds_header = NDSHeader(sys.argv[1])
nds_header.pretty_print()

nds_header.dump()
nds_header.parse_arm7i_overlay()

# Create ARM7 ELF
num_segs_added = 0
out_elf = ELF.parse("template.elf")
#out_elf.strip()

for s in sections_to_remove:
    try:
        out_elf.remove_section(s)
    except:
        pass

# Craft header info
header = out_elf.header
header.entrypoint = nds_header.arm7_entry
header.machine_type = ELF.ARCH.ARM
header.file_type = ELF.E_TYPE.EXECUTABLE
header.identity_data = ELF.ELF_DATA.LSB
header.identity_os_abi = ELF.OS_ABI.ARM

to_remove = []
for e in out_elf.dynamic_entries:
    print (e)
    if e.tag != ELF.DYNAMIC_TAGS.STRTAB and e.tag != ELF.DYNAMIC_TAGS.STRSZ and e.tag != ELF.DYNAMIC_TAGS.SYMTAB and e.tag != ELF.DYNAMIC_TAGS.SYMENT:
        to_remove += [e]

print ("---")
for e in to_remove:
    out_elf.remove(e)

for e in out_elf.dynamic_entries:
    print (e)

def add_seg(name, seg):
    global num_segs_added, out_elf
    
    magic_virt = 0x12345678
    
    sect_type = ELF.SECTION_TYPES.NOBITS
    if seg.content != []:
        sect_type = ELF.SECTION_TYPES.PROGBITS
    
    section = ELF.Section(name, sect_type)
    section.virtual_address = seg.virtual_address
    
    section.add(ELF.SECTION_FLAGS.WRITE)
    section.add(ELF.SECTION_FLAGS.ALLOC)
    should_load = False
    if seg.content != []:
        section.content = seg.content
        section.add(ELF.SECTION_FLAGS.EXECINSTR)
        should_load = True
    section.alignment = 4
    section.size = seg.virtual_size
    out_elf.add(section, should_load)
    
    virt_size = seg.virtual_size
    virt_addr = seg.virtual_address
    
    # Keep LIEF from aligning to page size
    sect = None
    for s in out_elf.sections:
        if s.name == name:
            sect = s
            break
    
    for s in sect.segments:
        if s.virtual_address == seg.virtual_address:
            s.virtual_size = seg.virtual_size
            s.physical_size = seg.physical_size
            seg = s
            break

    
    if sect_type == ELF.SECTION_TYPES.NOBITS:
        out_elf.add(seg)
    else:
        sect.size = virt_size

    for s in out_elf.segments:
        if s.virtual_address == seg.virtual_address:
            seg = s

    if sect_type == ELF.SECTION_TYPES.NOBITS:
        sect.file_offset = 0
        seg.file_offset = 0
        seg.virtual_size = virt_size
        #sect.size = virt_size
        seg.content = []
    else:
        seg.physical_size = virt_size
        seg.virtual_size = virt_size

def add_seg_old(seg):
    global num_segs_added, out_elf
    if num_segs_added == 0:
        first_seg = None
        for s in out_elf.segments:
            first_seg = s
            break;
    
        out_elf.replace(seg, first_seg)
    elif num_segs_added == 1:
        first_seg = None
        for s in out_elf.segments:
            first_seg = s
            break;
    
        out_elf.replace(seg, first_seg)
    else:
        out_elf.add(seg)

    # Keep LIEF from aligning to page size
    for s in out_elf.segments:
        if s.type == ELF.SEGMENT_TYPES.NOTE:
            s.virtual_size = seg.virtual_size
            s.physical_size = 0
            s.content = []
            s.file_offset = 0
            seg = s
            continue
        if s.virtual_address == seg.virtual_address:
            s.virtual_size = seg.virtual_size
            s.physical_size = seg.physical_size
            seg = s
            break

    num_segs_added += 1

def add_func_sym(name, addr):
    s = out_elf.add_exported_function(addr, name)
    
    sect = out_elf.section_from_virtual_address(addr)
    shndx = 0
    for sect_iter in out_elf.sections:
        if sect_iter == sect:
            break
        shndx += 1
    
    print (sect)
    s.shndx = shndx
    print (s)
    out_elf.add_static_symbol(s)

def add_sect_sym(sect):
    s = ELF.Symbol()
    s.value = sect.virtual_address
    s.size = 0
    s.type = ELF.SYMBOL_TYPES.SECTION
    shndx = 0
    for sect_iter in out_elf.sections:
        if sect_iter == sect:
            break
        shndx += 1
    if shndx == 0:
        s.type = ELF.SYMBOL_TYPES.NOTYPE
    s.shndx = shndx
    s.name = sect.name
    out_elf.add_static_symbol(s)

def add_var_sym(name, addr, size):
    s = ELF.Symbol()
    s.value = addr
    s.size = size
    s.type = ELF.SYMBOL_TYPES.OBJECT
    
    shndx = 0
    try:
        sect = out_elf.section_from_virtual_address(addr)
        for sect_iter in out_elf.sections:
            if sect_iter == sect:
                break
            shndx += 1
    except:
        shndx = 0
        for seg in out_elf.segments:
            if addr >= seg.virtual_address and addr < seg.virtual_address + seg.virtual_size:
                break
        for sect_iter in out_elf.sections:
            if sect_iter.virtual_address == seg.virtual_address:
                break
            shndx += 1

    s.shndx = shndx
    s.name = name
    out_elf.add_static_symbol(s)

add_seg_old(make_load(bytes([0]*0x1000), 0x1000))
add_seg_old(make_load(bytes([0]*0x1000), 0x2000))

# Add segments
add_seg(".arm7", make_load(nds_header.arm7_data, nds_header.arm7_load))
#add_seg(".arm7i", make_load(nds_header.arm7i_data, nds_header.arm7i_load))

# ARM7i segments
if nds_header.is_dsi():
    idx = 0
    for s in nds_header.arm7i_overlay_segs:
        real_addr, addr, size, data_seek, dat = s

        print (hex(real_addr), hex(size), hex(data_seek), hex(addr))
        
        if dat is None:
            add_seg(".arm7i.seg" + str(idx), make_memory(real_addr, size))
        else:
            add_seg(".arm7i.seg" + str(idx), make_load(dat, real_addr))
        
        idx += 1

add_seg(".arm9", make_load(nds_header.arm9_data, nds_header.arm9_load))
if nds_header.is_dsi():
    add_seg(".arm9i", make_load(nds_header.arm9i_data, nds_header.arm9i_load))

add_seg(".mmem", make_memory(0x02000000, 0x1000000))
add_seg(".swram", make_memory(0x03000000, 0xC8000))
add_seg(".io", make_memory(0x04000000, 0x800000))
add_seg(".debug_ram", make_memory(0xD000000, 0x1000000))
add_seg(".palette", make_memory(0x05000000, 0x800))
add_seg(".vram", make_memory(0x06000000, 0x01000000))
add_seg(".oam", make_memory(0x07000000, 0x1000))
add_seg(".gba", make_memory(0x08000000, 0x02000000))
add_seg(".gba_sram", make_memory(0x0A000000, 0x20000))

# Set up symbols correctly
sym_sectidx = len(out_elf.sections)
sym_sect = ELF.Section(".symtab", ELF.SECTION_TYPES.SYMTAB)
sym_sect.alignment = 4
sym_sect.link = 1#sym_sectidx-1
sym_sect.entry_size = 0x10
out_elf.add(sym_sect, False)
sym_sect = out_elf.get_section(".symtab")
sym_sect.information = 10

for s in out_elf.sections:
    add_sect_sym(s)
add_func_sym("arm9_start", nds_header.arm9_entry)

if len(sys.argv) > 2:
    for line in open(sys.argv[2], encoding="shift-jis").read().split("\n"):
        vals = line.split(" ")
        if len(vals) < 3:
            continue
        addr = int(vals[0], 16)
        name = vals[1]
        size = int(vals[2])
        add_var_sym(name, addr, size)

# Purge old segments
#add_seg_old(make_memory(0xFFFFFFFF, 0))
#add_seg_old(make_memory(0xFFFFFFFF, 0))

out_elf.write(sys.argv[1] + ".elf")
