#!/usr/bin/env python3
"""두 Rust 파일에 중복 정의된 serde 타입(enum 변형/struct 필드)의 차이를 보고한다.

CLI(src/cli/src/api.rs)가 common(src/common/api.rs)의 타입을 복제해 쓰고 있으므로,
한쪽만 수정되면 JSON 직렬화가 런타임에 깨진다. 이 스크립트는 그 drift를 정적으로 잡는다.

사용법:
  api_drift.py <a.rs> <b.rs>
  api_drift.py src/common/api.rs src/cli/src/api.rs
종료 코드: 0 = 일치, 1 = 불일치 발견
"""
import re
import sys


def strip_comments(s):
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    return re.sub(r"//[^\n]*", "", s)


def block(src, start):
    depth, i = 0, start
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start + 1: i]
        i += 1
    return ""


def fields(body):
    out = {}
    for m in re.finditer(r"(?:pub\s+)?(\w+)\s*:\s*([^,]+?)\s*(?:,|$)", body.strip()):
        out[m.group(1)] = re.sub(r"\s+", "", m.group(2))
    return out


def parse(path):
    src = strip_comments(open(path, encoding="utf-8").read())
    types = {}
    for m in re.finditer(r"pub\s+(struct|enum)\s+(\w+)[^{;]*\{", src):
        kind, name = m.group(1), m.group(2)
        body = block(src, m.end() - 1)
        if kind == "struct":
            types[name] = ("struct", fields(body))
        else:
            variants, i = {}, 0
            for vm in re.finditer(r"(\w+)\s*(\{|\(|,|$)", body):
                if vm.start() < i:
                    continue
                vname, tok = vm.group(1), vm.group(2)
                if tok == "{":
                    inner = block(body, vm.end() - 1)
                    variants[vname] = fields(inner)
                    i = vm.end() + len(inner) + 1
                elif tok == "(":
                    close = body.index(")", vm.end())
                    variants[vname] = {"0": re.sub(r"\s+", "", body[vm.end():close])}
                    i = close + 1
                else:
                    variants[vname] = {}
                    i = vm.end()
            types[name] = ("enum", variants)
    return types


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    a, b = parse(sys.argv[1]), parse(sys.argv[2])
    issues = []
    for name in sorted(set(a) & set(b)):
        ka, da = a[name]
        kb, db = b[name]
        if ka != kb:
            issues.append(f"{name}: kind {ka} vs {kb}")
            continue
        if ka == "struct":
            for f in sorted(set(da) | set(db)):
                if da.get(f) != db.get(f):
                    issues.append(f"{name}.{f}: {da.get(f, '<missing>')} vs {db.get(f, '<missing>')}")
        else:
            for v in sorted(set(da) | set(db)):
                if v not in da or v not in db:
                    issues.append(f"{name}::{v}: {'present' if v in da else '<missing>'} vs {'present' if v in db else '<missing>'}")
                    continue
                for f in sorted(set(da[v]) | set(db[v])):
                    if da[v].get(f) != db[v].get(f):
                        issues.append(f"{name}::{v}.{f}: {da[v].get(f, '<missing>')} vs {db[v].get(f, '<missing>')}")
    shared = sorted(set(a) & set(b))
    print(f"shared types: {', '.join(shared) or '(none)'}")
    print(f"only in {sys.argv[1]}: {', '.join(sorted(set(a) - set(b))) or '-'}")
    print(f"only in {sys.argv[2]}: {', '.join(sorted(set(b) - set(a))) or '-'}")
    if issues:
        print("DRIFT:")
        for i in issues:
            print("  - " + i)
        sys.exit(1)
    print("OK: shared types match")


if __name__ == "__main__":
    main()
