#!/usr/bin/env python3
"""C 구조체 레이아웃(sizeof/offsetof)을 호스트 clang으로 계산해 JSON으로 출력한다.

BPF 타깃(bpfel)과 x86_64/arm64 호스트는 __u8~__u64 정렬 규칙이 같으므로
호스트에서 계산한 레이아웃을 커널/BPF 맵 값 레이아웃으로 간주해도 된다.

사용법:
  struct_layout.py <c_or_h_file> <struct_name> [<struct_name> ...]
  struct_layout.py include/swift_guard.h filter_rule prefix_key if_redirect filter_stats

파일 전체를 include하지 않고 지정한 struct 블록과 #define만 추출하므로
linux/bpf.h 같은 커널 헤더가 없는 macOS에서도 동작한다.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

PRELUDE = """
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t __u8; typedef uint16_t __u16; typedef uint32_t __u32; typedef uint64_t __u64;
typedef int8_t __s8; typedef int16_t __s16; typedef int32_t __s32; typedef int64_t __s64;
"""


def extract_struct(src: str, name: str) -> str:
    m = re.search(r"struct\s+" + re.escape(name) + r"\s*\{", src)
    if not m:
        raise SystemExit(f"struct {name} not found")
    depth, i = 0, m.end() - 1
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                end = src.index(";", i)
                return src[m.start(): end + 1]
        i += 1
    raise SystemExit(f"unbalanced braces in struct {name}")


def field_names(body: str) -> list:
    inner = body[body.index("{") + 1: body.rindex("}")]
    inner = re.sub(r"/\*.*?\*/", "", inner, flags=re.S)
    inner = re.sub(r"//[^\n]*", "", inner)
    names = []
    for decl in inner.split(";"):
        decl = decl.strip()
        if not decl or ":" in decl:  # 비트필드는 offsetof 불가 → 생략
            continue
        m = re.search(r"([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$", decl)
        if m:
            names.append(m.group(1))
    return names


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    path, names = sys.argv[1], sys.argv[2:]
    src = open(path, encoding="utf-8").read()
    defines = "\n".join(l for l in src.splitlines() if re.match(r"\s*#define\s+\w+\s+\S", l))

    # 의존 struct(중첩)도 함께 추출: 요청된 것 외에 파일 내 모든 struct를 순서대로 포함
    all_names = re.findall(r"struct\s+(\w+)\s*\{", src)
    blocks = []
    for n in all_names:
        try:
            blocks.append(extract_struct(src, n))
        except SystemExit:
            pass

    prog = [PRELUDE, defines, *blocks, "int main(void){", 'printf("{");']
    for si, n in enumerate(names):
        body = extract_struct(src, n)
        sep = "," if si else ""
        prog.append(f'printf("{sep}\\"{n}\\":{{\\"size\\":%zu,\\"align\\":%zu,\\"fields\\":{{", sizeof(struct {n}), _Alignof(struct {n}));')
        for fi, f in enumerate(field_names(body)):
            fsep = "," if fi else ""
            prog.append(
                f'printf("{fsep}\\"{f}\\":[%zu,%zu]", offsetof(struct {n}, {f}), sizeof(((struct {n}*)0)->{f}));'
            )
        prog.append('printf("}}");')
    prog.append('printf("}\\n"); return 0; }')

    with tempfile.TemporaryDirectory() as d:
        c, exe = os.path.join(d, "l.c"), os.path.join(d, "l")
        open(c, "w").write("\n".join(prog))
        r = subprocess.run(["clang", "-w", "-o", exe, c], capture_output=True, text=True)
        if r.returncode:
            sys.stderr.write(r.stderr)
            sys.exit(1)
        out = subprocess.run([exe], capture_output=True, text=True, check=True).stdout
    print(json.dumps(json.loads(out), indent=2))


if __name__ == "__main__":
    main()
