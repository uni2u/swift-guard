#!/usr/bin/env python3
"""Swift-Guard Tier 3 결과 분석기.

tools/bench/basic_throughput_test.sh, rule_scaling_test.sh 가 만든 결과 디렉토리
(docs/poc-plan.md "결과 파일" 참고)를 읽어 summary.md 와 그래프(PNG)를 만든다.

사용법:
  python3 tools/analysis/analyze_performance.py [--results-dir ./results]
                                                [--output-dir <results-dir>/plots] [--no-plots]
의존: 표준 라이브러리 + matplotlib(그래프용, 없으면 summary.md 만). pip install -r tools/analysis/requirements.txt
종료 코드: 하나라도 분석했으면 0, 입력이 하나도 없으면 1.
"""

import argparse
import csv
import glob
import os
import re
import sys

THROUGHPUT_HEADER = [
    "packet_size", "generator", "mode", "rule_action", "duration_sec", "samples", "pps", "pps_peak",
    "gbps", "cpu_util", "cpu_softirq", "cpu_busiest", "if_rx_pps", "daemon_rss_kb",
]
RULE_SCALING_HEADER = [
    "rule_count", "side", "packet_size", "generator", "mode", "rule_action", "duration_sec", "samples",
    "pps", "pps_peak", "gbps", "cpu_util", "cpu_softirq", "cpu_busiest", "if_rx_pps", "daemon_rss_kb",
    "rules_added", "add_rules_sec", "add_rule_us_avg",
]
STATS_HEADER = ["timestamp_ms", "total_packets", "total_bytes", "pps", "mbps"]
FLOW_BANNER = "FLOW CHECK ONLY (lab generator) — not a performance result"

# 색: dataviz 기본 팔레트 categorical 순서 (blue, orange, aqua, yellow, magenta, green)
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"]
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e4e3df"
SURFACE = "#fcfcfb"


def num(v, default=None):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def read_csv(path, header):
    """(rows, skip_reason). header 가 다르면 rows=None."""
    if not os.path.isfile(path):
        return None, "skip: %s 없음" % os.path.basename(path)
    with open(path, newline="") as f:
        r = csv.reader(f)
        try:
            got = next(r)
        except StopIteration:
            return None, "skip: %s 비어 있음" % os.path.basename(path)
        if got != header:
            return None, "skip: %s 열 불일치(기대: %s)" % (os.path.basename(path), ",".join(header))
        rows = [dict(zip(header, row)) for row in r if row]
    if not rows:
        return None, "skip: %s 데이터 행 없음" % os.path.basename(path)
    return rows, None


def read_meta(path):
    meta = {}
    if os.path.isfile(path):
        with open(path) as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    meta[k] = v
    return meta


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def mpps(pps):
    return (num(pps, 0.0) or 0.0) / 1e6


# ---------------------------------------------------------------- plotting
class Plotter:
    def __init__(self, out_dir, flow_only):
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        self.plt = plt
        self.out_dir = out_dir
        self.flow_only = flow_only
        self.files = []
        plt.rcParams.update({
            "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
            "axes.edgecolor": GRID, "axes.labelcolor": INK2, "axes.titlecolor": INK,
            "xtick.color": INK2, "ytick.color": INK2, "text.color": INK,
            "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
            "axes.spines.top": False, "axes.spines.right": False,
            "lines.linewidth": 2, "lines.markersize": 7, "font.size": 10,
            "legend.frameon": False,
        })

    def figure(self, ncols, title):
        fig, axes = self.plt.subplots(1, ncols, figsize=(5.5 * ncols, 4.2), squeeze=False)
        if self.flow_only:
            title = "%s\n%s" % (title, FLOW_BANNER)
        fig.suptitle(title, color="#b3261e" if self.flow_only else INK, fontsize=11)
        return fig, axes[0]

    def save(self, fig, name):
        fig.tight_layout()
        path = os.path.join(self.out_dir, name)
        fig.savefig(path, dpi=120)
        self.plt.close(fig)
        self.files.append(name)
        print("  wrote %s" % path)


def plot_throughput(p, rows):
    sizes = [int(num(r["packet_size"], 0)) for r in rows]
    xs = list(range(len(sizes)))
    fig, (a1, a2) = p.figure(2, "Swift-Guard XDP throughput by frame size")
    for ax, key, label, scale in ((a1, "pps", "Mpps (matched packets)", 1e6), (a2, "gbps", "Gbps (L2 bytes, not line rate)", 1)):
        vals = [(num(r[key], 0.0) or 0.0) / scale for r in rows]
        ax.bar(xs, vals, width=0.6, color=SERIES[0], edgecolor=SURFACE, linewidth=2)
        ax.set_xticks(xs)
        ax.set_xticklabels([str(s) for s in sizes])
        ax.set_xlabel("frame size (bytes, incl. FCS)")
        ax.set_ylabel(label)
        ax.set_axisbelow(True)
        ax.grid(axis="x", visible=False)
    p.save(fig, "throughput.png")

    fig, (ax,) = p.figure(1, "CPU utilisation during measurement")
    for i, (key, label) in enumerate((("cpu_util", "all CPUs busy %"), ("cpu_busiest", "busiest CPU %"))):
        ax.plot(xs, [num(r[key], 0.0) for r in rows], marker="o", color=SERIES[i], label=label)
    ax.set_xticks(xs)
    ax.set_xticklabels([str(s) for s in sizes])
    ax.set_xlabel("frame size (bytes, incl. FCS)")
    ax.set_ylabel("CPU %")
    ax.set_ylim(0, 105)
    ax.legend()
    p.save(fig, "throughput_cpu.png")


def plot_timeseries(p, series):
    fig, (ax,) = p.figure(1, "xdp-filter stats: pps per 1 s sample")
    for i, (size, pts) in enumerate(series):
        color = SERIES[i % len(SERIES)] if i < len(SERIES) else INK2
        ax.plot([t for t, _ in pts], [v / 1e6 for _, v in pts], marker="o", markersize=4,
                color=color, label="%s B" % size)
    ax.set_xlabel("seconds since first sample")
    ax.set_ylabel("Mpps")
    ax.legend()
    p.save(fig, "throughput_timeseries.png")


def plot_rule_scaling(p, rows, base_pps):
    counts = [int(num(r["rule_count"], 0)) for r in rows]
    vals = [mpps(r["pps"]) for r in rows]
    fig, (a1, a2) = p.figure(2, "Rule scaling (side=%s, %s B)" % (rows[0]["side"], rows[0]["packet_size"]))
    a1.plot(counts, vals, marker="o", color=SERIES[0])
    a1.set_ylabel("Mpps (matched packets)")
    rel = [(num(r["pps"], 0.0) or 0.0) / base_pps * 100 if base_pps else 0.0 for r in rows]
    a2.plot(counts, rel, marker="o", color=SERIES[0])
    a2.axhline(100, color=INK2, linewidth=1, linestyle="--")
    a2.set_ylabel("%% of first step (%d rules)" % counts[0])
    a1.set_ylim(bottom=0)
    a2.set_ylim(0, max(110.0, max(rel) * 1.05))
    for ax in (a1, a2):
        ax.set_xscale("log")
        ax.set_xlabel("rules in map (log)")
    p.save(fig, "rule_scaling.png")


def plot_rule_add(p, rows):
    pts = [(int(num(r["rule_count"], 0)), num(r["add_rule_us_avg"])) for r in rows]
    pts = [(c, v) for c, v in pts if v is not None]
    if not pts:
        print("  skip: rule_add_latency.png (add_rule_us_avg 값 없음)")
        return
    fig, (ax,) = p.figure(1, "Rule add time per rule (incl. CLI process + TCP connect)")
    ax.plot([c for c, _ in pts], [v for _, v in pts], marker="o", color=SERIES[1])
    ax.set_xscale("log")
    ax.set_xlabel("rules in map after step (log)")
    ax.set_ylabel("µs per rule (add_rule_us_avg)")
    ax.set_ylim(bottom=0)
    p.save(fig, "rule_add_latency.png")


# ---------------------------------------------------------------- main
def load_timeseries(results_dir):
    out = []
    files = glob.glob(os.path.join(results_dir, "throughput", "stats_*.csv"))

    def key(path):
        m = re.search(r"stats_(\d+)\.csv$", path)
        return int(m.group(1)) if m else 0

    for path in sorted(files, key=key):
        rows, why = read_csv(path, STATS_HEADER)
        if rows is None:
            print("  %s" % why)
            continue
        t0 = num(rows[0]["timestamp_ms"], 0.0)
        pts = [((num(r["timestamp_ms"], 0.0) - t0) / 1000.0, num(r["pps"])) for r in rows]
        pts = [(t, v) for t, v in pts if v is not None]
        if pts:
            out.append((key(path), pts))
    return out


def main():
    sys.stdout.reconfigure(line_buffering=True)   # stderr 경고와 출력 순서를 맞춘다
    ap = argparse.ArgumentParser(description="Swift-Guard Tier 3 결과 분석 (summary.md + PNG)")
    ap.add_argument("--results-dir", default="./results", help="벤치 결과 디렉토리 (기본 ./results)")
    ap.add_argument("--output-dir", default=None, help="출력 디렉토리 (기본 <results-dir>/plots)")
    ap.add_argument("--no-plots", action="store_true", help="그래프를 만들지 않고 summary.md 만")
    args = ap.parse_args()
    out_dir = args.output_dir or os.path.join(args.results_dir, "plots")

    tp_rows, tp_why = read_csv(os.path.join(args.results_dir, "throughput_results.csv"), THROUGHPUT_HEADER)
    rs_rows, rs_why = read_csv(os.path.join(args.results_dir, "rule_scaling_results.csv"), RULE_SCALING_HEADER)
    for why in (tp_why, rs_why):
        if why:
            print(why)
    if tp_rows is None and rs_rows is None:
        print("분석할 입력이 없다 (%s)" % args.results_dir, file=sys.stderr)
        return 1

    flow_only = any(r["generator"] == "lab" for r in (tp_rows or []) + (rs_rows or []))
    os.makedirs(out_dir, exist_ok=True)

    plotter = None
    if args.no_plots:
        print("--no-plots: 그래프 생략, summary.md 만 생성")
    else:
        try:
            plotter = Plotter(out_dir, flow_only)
        except ImportError:
            print("WARN: matplotlib 없음 → 그래프 생략, summary.md 만 생성 (pip install -r tools/analysis/requirements.txt)",
                  file=sys.stderr)

    md = ["# Swift-Guard benchmark summary", ""]
    if flow_only:
        md += ["> **%s**" % FLOW_BANNER, "> 수치는 veth + python 송신 한계이며 성능 결과로 쓰지 않는다.", ""]
    md += ["- pps/gbps: `xdp-filter stats` 총계의 초당 차이. 전역 통계는 **룰에 매치한 패킷만** 센다.",
           "- gbps 바이트 기준은 XDP가 보는 L2 프레임(FCS·프리앰블·IFG 제외) — 선로 속도 아님.",
           "- if_rx_pps: 인터페이스 rx 카운터(드라이버마다 XDP_DROP 계수 여부가 다름 — 참고용).", ""]

    if tp_rows is not None:
        meta = read_meta(os.path.join(args.results_dir, "meta_throughput.txt"))
        md += ["## Basic throughput", ""]
        if meta:
            md += [md_table(["key", "value"], sorted(meta.items())), ""]
        md += [md_table(["frame B", "generator", "mode", "rule", "samples", "Mpps", "peak Mpps", "Gbps",
                         "CPU %", "softirq %", "busiest CPU %", "if_rx Mpps", "daemon RSS kB"],
                        [[r["packet_size"], r["generator"], r["mode"], r["rule_action"], r["samples"],
                          "%.3f" % mpps(r["pps"]), "%.3f" % mpps(r["pps_peak"]), r["gbps"], r["cpu_util"],
                          r["cpu_softirq"], r["cpu_busiest"], "%.3f" % mpps(r["if_rx_pps"]), r["daemon_rss_kb"]]
                         for r in tp_rows]), ""]
        if plotter:
            plot_throughput(plotter, tp_rows)
            ts = load_timeseries(args.results_dir)
            if ts:
                plot_timeseries(plotter, ts)
            else:
                print("  skip: throughput/stats_*.csv 없음 → throughput_timeseries.png 생략")

    if rs_rows is not None:
        meta = read_meta(os.path.join(args.results_dir, "meta_rule_scaling.txt"))
        base = num(rs_rows[0]["pps"], 0.0) or 0.0
        md += ["## Rule scaling", ""]
        if meta:
            md += [md_table(["key", "value"], sorted(meta.items())), ""]
        md += [md_table(["rules", "side", "frame B", "generator", "Mpps", "vs first %", "CPU %", "busiest CPU %",
                         "rules added", "add sec", "µs/rule (incl. CLI)"],
                        [[r["rule_count"], r["side"], r["packet_size"], r["generator"], "%.3f" % mpps(r["pps"]),
                          ("%.1f" % ((num(r["pps"], 0.0) or 0.0) / base * 100)) if base else "n/a",
                          r["cpu_util"], r["cpu_busiest"], r["rules_added"], r["add_rules_sec"] or "-",
                          r["add_rule_us_avg"] or "-"] for r in rs_rows]), ""]
        md += ["add_rule_us_avg 는 `xdp-filter add-rule` 프로세스 생성·TCP 연결을 포함한다(순수 맵 갱신 지연 아님).", ""]
        if plotter:
            plot_rule_scaling(plotter, rs_rows, base)
            plot_rule_add(plotter, rs_rows)

    skipped = [w for w in (tp_why, rs_why) if w]
    if skipped:
        md += ["## Skipped", ""] + ["- %s" % w for w in skipped] + [""]
    if plotter and plotter.files:
        md += ["## Plots", ""] + ["- [%s](%s)" % (f, f) for f in plotter.files] + [""]

    summary = os.path.join(out_dir, "summary.md")
    with open(summary, "w") as f:
        f.write("\n".join(md))
    print("wrote %s" % summary)
    if flow_only:
        print(FLOW_BANNER)
    return 0


if __name__ == "__main__":
    sys.exit(main())
