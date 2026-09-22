#!/usr/bin/env python3
"""Deterministic triage pass for one artifact. Emits triage JSON to stdout (or -o).

Never assumes .bin == raw MCU firmware. Never infers architecture from filename.
Records format, size, SHA-256, entropy (whole-file + windowed), detected containers,
embedded signatures, string/endpoint teaser, and ELF/PE facts when applicable.
This is orientation for the orchestrator + triage specialist, not a finding.
"""
import sys, os, json, math, hashlib, subprocess, re, argparse

MAGICS = [
    (b"\x7fELF", "ELF"), (b"MZ", "PE/DOS (MZ)"), (b"\xca\xfe\xba\xbe", "Mach-O FAT / Java class"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32"), (b"\xfe\xed\xfa\xcf", "Mach-O 64"),
    (b"PK\x03\x04", "ZIP/JAR/APK/OTA-zip"), (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"), (b"\x28\xb5\x2f\xfd", "zstd"), (b"\x89PNG", "PNG"),
    (b"\x27\x05\x19\x56", "uImage (U-Boot legacy)"), (b"\xd0\x0d\xfe\xed", "Android boot / dtb-ish"),
    (b"\xd1\x0d\xff\xfe", "?"), (b"ANDROID!", "Android boot image"),
    (b"hsqs", "SquashFS LE"), (b"sqsh", "SquashFS BE"), (b"\x85\x19", "JFFS2 LE"),
    (b"UBI#", "UBIfs / UBI"), (b"\xe9", "x86 boot / MBR-ish (weak)"),
    (b"\xea\x32", "ARM reset vector-ish (weak)"), (b"\xd3\x18", "?"),
    (b"\x51\x4d\x62\x33", "QEMU QCOW"), (b"\xed\xab\xee\xdb", "RPM"),
    (b"CrAU", "Chrome OS / Android A/B OTA payload (CrAU)"),
    (b"\x06\x05\x04\x03\x02\x07\x08", "esp-idf-ish"),
]

def sha256(path, cap=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b: break
            h.update(b)
    return h.hexdigest()

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b]+=1
    n=len(data); e=0.0
    for c in freq:
        if c: p=c/n; e-=p*math.log2(p)
    return round(e,3)

def windowed_entropy(path, win=4096, step=None, maxwins=4096):
    step = step or win
    highs=[]; total=0; hi=0
    with open(path,"rb") as f:
        i=0
        while True:
            chunk=f.read(win)
            if not chunk: break
            e=entropy(chunk); total+=1
            if e>=7.4: hi+=1
            if len(highs)<64 and e>=7.4: highs.append({"offset":i,"entropy":e})
            i+=step; f.seek(i)
            if total>=maxwins: break
    return {"windows_sampled":total,"high_entropy_windows":hi,
            "high_entropy_ratio":round(hi/total,3) if total else 0.0,
            "high_entropy_examples":highs[:16]}

def run(cmd, timeout=120):
    try:
        p=subprocess.run(cmd,capture_output=True,timeout=timeout)
        return p.stdout.decode("utf-8","replace"), p.returncode
    except Exception as e:
        return f"<error: {e}>", -1

def detect_magic(head):
    hits=[]
    for sig,name in MAGICS:
        if head.startswith(sig): hits.append({"at":0,"sig":sig.hex(),"guess":name})
    return hits

def endpoint_teaser(strings_out):
    # NOT the endpoint analysis — just a teaser count so the orchestrator routes.
    pats={
      "url":r"[a-z][a-z0-9+.\-]*://[^\s\"'<>]{4,}",
      "host":r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
      "ipv4":r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
      "ipv6":r"\b(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}\b",
    }
    out={}
    for k,p in pats.items():
        m=set(re.findall(p,strings_out,re.I))
        out[k]={"count":len(m),"examples":sorted(m)[:12]}
    return out

def elf_facts(path):
    try:
        from elftools.elf.elffile import ELFFile
        with open(path,"rb") as f:
            e=ELFFile(f)
            return {"class":e.elfclass,"endian":"little" if e.little_endian else "big",
                    "machine":e.header["e_machine"],"type":e.header["e_type"],
                    "entry":hex(e.header["e_entry"]),
                    "sections":[s.name for s in e.iter_sections() if s.name][:40]}
    except Exception as ex:
        return {"error":str(ex)}

def pe_facts(path):
    try:
        import pefile
        pe=pefile.PE(path,fast_load=True); pe.parse_data_directories()
        machine=pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine,pe.FILE_HEADER.Machine)
        subsys=pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem,pe.OPTIONAL_HEADER.Subsystem)
        dlls=[]
        if hasattr(pe,"DIRECTORY_ENTRY_IMPORT"):
            dlls=[e.dll.decode("utf-8","replace") for e in pe.DIRECTORY_ENTRY_IMPORT][:40]
        dotnet = hasattr(pe,"DIRECTORY_ENTRY_COM_DESCRIPTOR") and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR is not None
        return {"machine":str(machine),"subsystem":str(subsys),
                "is_dll":bool(pe.is_dll()),"is_driver":bool(pe.is_driver()),
                "dotnet":bool(dotnet),"timestamp":pe.FILE_HEADER.TimeDateStamp,
                "imported_dlls":dlls}
    except Exception as ex:
        return {"error":str(ex)}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("artifact"); ap.add_argument("-o","--out")
    ap.add_argument("--strings-min",type=int,default=6)
    a=ap.parse_args()
    path=a.artifact
    if not os.path.isfile(path):
        print(json.dumps({"error":f"not a file: {path}"})); sys.exit(2)
    size=os.path.getsize(path)
    with open(path,"rb") as f: head=f.read(64)
    with open(path,"rb") as f: whole = f.read(min(size, 8<<20))
    file_out,_=run(["file","-b",path])
    strings_out,_=run(["strings","-a","-n",str(a.strings_min),path],timeout=180)
    bw_out,bw_rc=run(["binwalk",path],timeout=240)
    res={
      "artifact":os.path.abspath(path),
      "filename":os.path.basename(path),
      "size_bytes":size,
      "sha256":sha256(path),
      "file_cmd":file_out.strip(),
      "magic_hits":detect_magic(head),
      "head_hex":head.hex(),
      "entropy_sampled":entropy(whole),
      "windowed_entropy":windowed_entropy(path),
      "binwalk":{"rc":bw_rc,"signatures":[l for l in bw_out.splitlines() if l.strip() and not l.startswith("DECIMAL") and "----" not in l][:80]},
      "strings_count":strings_out.count("\n"),
      "endpoint_teaser":endpoint_teaser(strings_out),
      "format_class":None,
      "notes":[],
    }
    fc=file_out.lower()
    if head.startswith(b"\x7fELF"): res["format_class"]="ELF"; res["elf"]=elf_facts(path)
    elif head.startswith(b"MZ"):    res["format_class"]="PE"; res["pe"]=pe_facts(path)
    elif head.startswith((b"PK\x03\x04",)): res["format_class"]="archive/zip-family"
    elif any(head.startswith(s) for s in (b"\x1f\x8b",b"BZh",b"\xfd7zXZ\x00",b"\x28\xb5\x2f\xfd")): res["format_class"]="compressed-stream"
    elif "squashfs" in bw_out.lower() or head.startswith((b"hsqs",b"sqsh")): res["format_class"]="filesystem/squashfs"
    elif "u-boot" in bw_out.lower() or head.startswith(b"\x27\x05\x19\x56"): res["format_class"]="firmware/uimage"
    else: res["format_class"]="unknown/raw"
    # advisory notes (never assume)
    if res["entropy_sampled"]>=7.4: res["notes"].append("HIGH whole-file entropy — likely compressed/encrypted/packed; confirm before disassembly.")
    if res["windowed_entropy"]["high_entropy_ratio"]>=0.6: res["notes"].append("Majority high-entropy windows — expect packed/encrypted regions; look for low-entropy header/config.")
    if res["format_class"]=="unknown/raw": res["notes"].append("Unknown/raw: DO NOT assume architecture. Route to triage specialist for arch/base/endianness hypotheses; consider MCU-RE + platform-research.")
    if path.lower().endswith(".bin"): res["notes"].append(".bin extension is not evidence of raw MCU firmware — format_class above is derived from content.")
    tot=sum(v["count"] for v in res["endpoint_teaser"].values())
    if tot>0: res["notes"].append(f"{tot} network-indicator strings seen — route Endpoint & Network specialist (teaser only; not the analysis).")
    js=json.dumps(res,indent=2)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)),exist_ok=True)
        with open(a.out,"w") as f: f.write(js)
        print(f"[triage] {res['filename']}  class={res['format_class']}  sha256={res['sha256'][:16]}…  -> {a.out}")
    else:
        print(js)

if __name__=="__main__": main()
