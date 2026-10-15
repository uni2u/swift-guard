#!/usr/bin/env python3
"""Swift-Guard Tier 3 결과 분석기.

tools/bench/basic_throughput_test.sh, rule_scaling_test.sh 가 만든 결과 디렉토리
(docs/poc-plan.md "결과 파일" 참고)를 읽어 summary.md 와 그래프(PNG)를 만든다.

사용법:
  python3 tools/analysis/analyze_performance.py [--results-dir ./results]
                                                [--output-dir <results-dir>/plots] [--no-plots]
의존: 표준 라이브러리 + matplotlib(그래프용, 없으면 summary.md 만). pip install -r tools/analysis/requirements.txt
종료 코드: 하나라도 분석했으면 0, 입력이 하나도 없으면 1.

신·구 결과를 모두 읽는다. 현재 요약 CSV는 맨 끝에 xdp_rx_pps,xdp_rx_pps_peak,xdp_rx_gbps 3열이 있고,
stats CSV는 17열(xdp_* 포함)이다. 이전 버전 결과(그 열이 없음)는 처리량 지표로 pps(룰 매치 기준)를 쓰고,
summary.md 와 그래프에 어느 지표를 썼는지 표시한다.
"""

import argparse
import csv
import glob
import os
import re
import sys

XDP_SUMMARY_COLS = ["xdp_rx_pps", "xdp_rx_pps_peak", "xdp_rx_gbps"]
THROUGHPUT_HEADER_V1 = [
    "packet_size", "generator", "mode", "rule_action", "duration_sec", "samples", "pps", "pps_peak",
    "gbps", "cpu_util", "cpu_softirq", "cpu_busiest", "if_rx_pps", "daemon_rss_kb",
]
THROUGHPUT_HEADER = THROUGHPUT_HEADER_V1 + XDP_SUMMARY_COLS
RULE_SCALING_HEADER_V1 = [
    "rule_count", "side", "packet_size", "generator", "mode", "rule_action", "duration_sec", "samples",
    "pps", "pps_peak", "gbps", "cpu_util", "cpu_softirq", "cpu_busiest", "if_rx_pps", "daemon_rss_kb",
    "rules_added", "add_rules_sec", "add_rule_us_avg",
]
RULE_SCALING_HEADER = RULE_SCALING_HEADER_V1 + XDP_SUMMARY_COLS
STATS_HEADER_V1 = ["timestamp_ms", "total_packets", "total_bytes", "pps", "mbps"]
STATS_HEADER = STATS_HEADER_V1 + [
    "xdp_rx_packets", "xdp_rx_bytes", "xdp_rx_pps", "xdp_rx_mbps", "xdp_drop_packets", "xdp_pass_packets",
    "xdp_redirect_packets", "xdp_count_packets", "xdp_no_match_packets", "xdp_invalid_packets",
    "xdp_non_ipv4_packets", "xdp_action_error_packets",
]
# 허용 헤더: 현재 → 이전 순서
THROUGHPUT_HEADERS = [THROUGHPUT_HEADER, THROUGHPUT_HEADER_V1]
RULE_SCALING_HEADERS = [RULE_SCALING_HEADER, RULE_SCALING_HEADER_V1]
STATS_HEADERS = [STATS_HEADER, STATS_HEADER_V1]
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


def read_csv(path, headers):
    """(rows, skip_reason). headers = 허용 헤더 목록(첫 번째가 현재 형식).
    파일 헤더가 그중 하나와 같으면 rows 의 각 dict 는 현재 형식(headers[0])의 모든 열을 갖고,
    파일에 없는 열은 None 이다. 어느 것과도 다르면 rows=None."""
    full = headers[0]
    if not os.path.isfile(path):
        return None, "skip: %s 없음" % os.path.basename(path)
    with open(path, newline="") as f:
        r = csv.reader(f)
        try:
            got = next(r)
        except StopIteration:
            return None, "skip: %s 비어 있음" % os.path.basename(path)
        if got not in headers:
            return None, "skip: %s 열 불일치(기대: %s)" % (os.path.basename(path), ",".join(full))
        rows = []
        for row in r:
            if not row:
                continue
            d = dict.fromkeys(full)
            d.update(zip(got, row))
            rows.append(d)
    if not rows:
        return None, "skip: %s 데이터 행 없음" % os.path.basename(path)
    return rows, None


def has_values(rows, col):
    """모든 행에 col 값(빈 칸 아님)이 있는가."""
    return all(r.get(col) not in (None, "") for r in rows)


class Metric:
    """처리량 지표 선택. xdp_rx_pps 열이 있으면(현재 형식) 그것, 없으면 pps(이전 형식, 룰 매치 기준)."""

    def __init__(self, rows):
        self.xdp = has_values(rows, "xdp_rx_pps")
        if self.xdp:
            self.pps, self.peak, self.gbps = "xdp_rx_pps", "xdp_rx_pps_peak", "xdp_rx_gbps"
            self.desc = "xdp_rx_pps (XDP가 본 전체 프레임, 룰 매치와 무관)"
            self.axis = "Mpps (xdp_rx_pps: all frames XDP saw)"
            self.gaxis = "Gbps (xdp_rx_gbps, L2 bytes, not line rate)"
        else:
            self.pps, self.peak, self.gbps = "pps", "pps_peak", "gbps"
            self.desc = "pps (이전 형식 결과: xdp_rx_* 열 없음 → 룰 매치 패킷 기준)"
            self.axis = "Mpps (pps: rule-matched packets, legacy result)"
            self.gaxis = "Gbps (gbps: rule-matched, L2 bytes)"


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


def plot_throughput(p, rows, metric):
    sizes = [int(num(r["packet_size"], 0)) for r in rows]
    xs = list(range(len(sizes)))
    fig, (a1, a2) = p.figure(2, "Swift-Guard XDP throughput by frame size")
    for ax, key, label, scale in ((a1, metric.pps, metric.axis, 1e6), (a2, metric.gbps, metric.gaxis, 1)):
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


def plot_timeseries(p, series, col):
    fig, (ax,) = p.figure(1, "xdp-filter stats: %s per 1 s sample" % col)
    for i, (size, pts) in enumerate(series):
        color = SERIES[i % len(SERIES)] if i < len(SERIES) else INK2
        ax.plot([t for t, _ in pts], [v / 1e6 for _, v in pts], marker="o", markersize=4,
                color=color, label="%s B" % size)
    ax.set_xlabel("seconds since first sample")
    ax.set_ylabel("Mpps (%s)" % col)
    ax.legend()
    p.save(fig, "throughput_timeseries.png")


def plot_rule_scaling(p, rows, base_pps, metric):
    counts = [int(num(r["rule_count"], 0)) for r in rows]
    vals = [mpps(r[metric.pps]) for r in rows]
    fig, (a1, a2) = p.figure(2, "Rule scaling (side=%s, %s B)" % (rows[0]["side"], rows[0]["packet_size"]))
    a1.plot(counts, vals, marker="o", color=SERIES[0])
    a1.set_ylabel(metric.axis)
    rel = [(num(r[metric.pps], 0.0) or 0.0) / base_pps * 100 if base_pps else 0.0 for r in rows]
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
    """[(size, [(t, pps)])], 사용한 열 이름. 모든 파일에 xdp_rx_pps 값이 있으면 그 열, 아니면 pps."""
    out = []
    files = glob.glob(os.path.join(results_dir, "throughput", "stats_*.csv"))

    def key(path):
        m = re.search(r"stats_(\d+)\.csv$", path)
        return int(m.group(1)) if m else 0

    loaded = []
    for path in sorted(files, key=key):
        rows, why = read_csv(path, STATS_HEADERS)
        if rows is None:
            print("  %s" % why)
            continue
        loaded.append((key(path), rows))
    # 첫 행의 비율 열은 빈 칸이므로 데이터 행 중 하나라도 값이 있으면 그 열을 쓴다
    col = "xdp_rx_pps" if loaded and all(
        any(r.get("xdp_rx_pps") not in (None, "") for r in rows) for _, rows in loaded) else "pps"
    for size, rows in loaded:
        t0 = num(rows[0]["timestamp_ms"], 0.0)
        pts = [((num(r["timestamp_ms"], 0.0) - t0) / 1000.0, num(r[col])) for r in rows]
        pts = [(t, v) for t, v in pts if v is not None]
        if pts:
            out.append((size, pts))
    return out, col


def main():
    sys.stdout.reconfigure(line_buffering=True)   # stderr 경고와 출력 순서를 맞춘다
    ap = argparse.ArgumentParser(description="Swift-Guard Tier 3 결과 분석 (summary.md + PNG)")
    ap.add_argument("--results-dir", default="./results", help="벤치 결과 디렉토리 (기본 ./results)")
    ap.add_argument("--output-dir", default=None, help="출력 디렉토리 (기본 <results-dir>/plots)")
    ap.add_argument("--no-plots", action="store_true", help="그래프를 만들지 않고 summary.md 만")
    args = ap.parse_args()
    out_dir = args.output_dir or os.path.join(args.results_dir, "plots")

    tp_rows, tp_why = read_csv(os.path.join(args.results_dir, "throughput_results.csv"), THROUGHPUT_HEADERS)
    rs_rows, rs_why = read_csv(os.path.join(args.results_dir, "rule_scaling_results.csv"), RULE_SCALING_HEADERS)
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
    md += ["- xdp_rx_pps/xdp_rx_gbps: XDP가 본 **전체 프레임**(xdp_stats_map RX 슬롯)의 초당 차이. 룰 매치와 무관한 "
           "**처리량 1차 지표**다.",
           "- pps/gbps: `xdp-filter stats` 총계(total_packets)의 초당 차이. **룰에 매치한 패킷만** 센다"
           "(--rule-action none 이면 0).",
           "- gbps 바이트 기준은 XDP가 보는 L2 프레임(FCS·프리앰블·IFG 제외) — 선로 속도 아님.",
           "- if_rx_pps: 인터페이스 rx 카운터(드라이버가 센 값. XDP_DROP 계수 여부가 드라이버마다 다름 — 참고용).",
           "- 이전 버전 결과(xdp_rx_* 열 없음)는 처리량 지표로 pps를 쓰고 섹션마다 표시한다.", ""]

    if tp_rows is not None:
        meta = read_meta(os.path.join(args.results_dir, "meta_throughput.txt"))
        metric = Metric(tp_rows)
        md += ["## Basic throughput", ""]
        if meta:
            md += [md_table(["key", "value"], sorted(meta.items())), ""]
        md += ["처리량 지표: **%s**" % metric.desc, ""]
        md += [md_table(["frame B", "generator", "mode", "rule", "samples", "Mpps", "peak Mpps", "Gbps",
                         "matched Mpps (pps)", "CPU %", "softirq %", "busiest CPU %", "if_rx Mpps", "daemon RSS kB"],
                        [[r["packet_size"], r["generator"], r["mode"], r["rule_action"], r["samples"],
                          "%.3f" % mpps(r[metric.pps]), "%.3f" % mpps(r[metric.peak]), r[metric.gbps],
                          "%.3f" % mpps(r["pps"]), r["cpu_util"], r["cpu_softirq"], r["cpu_busiest"],
                          "%.3f" % mpps(r["if_rx_pps"]), r["daemon_rss_kb"]]
                         for r in tp_rows]), ""]
        if plotter:
            plot_throughput(plotter, tp_rows, metric)
            ts, ts_col = load_timeseries(args.results_dir)
            if ts:
                plot_timeseries(plotter, ts, ts_col)
            else:
                print("  skip: throughput/stats_*.csv 없음 → throughput_timeseries.png 생략")

    if rs_rows is not None:
        meta = read_meta(os.path.join(args.results_dir, "meta_rule_scaling.txt"))
        metric = Metric(rs_rows)
        base = num(rs_rows[0][metric.pps], 0.0) or 0.0
        md += ["## Rule scaling", ""]
        if meta:
            md += [md_table(["key", "value"], sorted(meta.items())), ""]
        md += ["처리량 지표: **%s**" % metric.desc, ""]
        md += [md_table(["rules", "side", "frame B", "generator", "Mpps", "vs first %", "CPU %", "busiest CPU %",
                         "rules added", "add sec", "µs/rule (incl. CLI)"],
                        [[r["rule_count"], r["side"], r["packet_size"], r["generator"], "%.3f" % mpps(r[metric.pps]),
                          ("%.1f" % ((num(r[metric.pps], 0.0) or 0.0) / base * 100)) if base else "n/a",
                          r["cpu_util"], r["cpu_busiest"], r["rules_added"], r["add_rules_sec"] or "-",
                          r["add_rule_us_avg"] or "-"] for r in rs_rows]), ""]
        md += ["add_rule_us_avg 는 `xdp-filter add-rule` 프로세스 생성·TCP 연결을 포함한다(순수 맵 갱신 지연 아님).", ""]
        if plotter:
            plot_rule_scaling(plotter, rs_rows, base, metric)
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
