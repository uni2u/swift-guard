#!/usr/bin/env python3
"""README.md와 docs/**/*.md 의 내부 앵커(GitHub 규칙)·상대 링크(파일+앵커)를 점검한다.
코드 블록 안은 무시한다. 종료 코드: 0 = 깨진 링크 없음, 1 = 있음."""
import glob, os, re, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), *[".."] * 4))
os.chdir(ROOT)
def strip(s): return re.sub(r"```.*?```", "", s, flags=re.S)
def anchors(path):
    code = strip(open(path, encoding="utf-8").read())
    return {re.sub(r"[^\w\- ]", "", h.strip().lower()).replace(" ", "-")
            for h in re.findall(r"^#{1,6} (.+)$", code, flags=re.M)}
bad = 0; total = 0
for d in ["README.md"] + sorted(glob.glob("docs/**/*.md", recursive=True)):
    code = strip(open(d, encoding="utf-8").read()); own = anchors(d)
    for target, frag in re.findall(r"\]\(([^)#\s]*)(#[^)\s]+)?\)", code):
        if target.startswith(("http://", "https://", "mailto:")): continue
        total += 1
        if not target:
            if frag and frag[1:] not in own: print(f"{d}: broken anchor {frag}"); bad += 1
            continue
        p = os.path.normpath(os.path.join(os.path.dirname(d), target))
        if not os.path.exists(p): print(f"{d}: missing file {target}"); bad += 1
        elif frag and p.endswith(".md") and frag[1:] not in anchors(p):
            print(f"{d}: broken anchor {target}{frag}"); bad += 1
print(f"links checked: {total}, broken: {bad}")
sys.exit(1 if bad else 0)
