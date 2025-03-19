# Swift-Guard PoC 계획 및 벤치마킹 가이드

이 문서는 Swift-Guard 프로젝트의 Proof of Concept (PoC) 진행 및 SCIE 저널 투고를 위한 벤치마킹 계획을 설명합니다.

## 1. 테스트 환경 설정

### 테스트 환경 요구사항

- **물리 서버 설정**:
  - CPU: Intel Xeon E5-2680v4 이상 (최소 16코어)
  - RAM: 32GB 이상
  - NIC: Intel X520/X540/X550 계열 (10GbE 이상, XDP 지원)
  - SSD: 256GB 이상

- **소프트웨어 환경**:
  - 운영체제: Ubuntu 22.04 LTS 또는 최신 Debian
  - 커널 버전: 5.15 이상 (XDP 기능 완전 지원)
  - 패키지: clang, llvm, libelf-dev, build-essential, linux-headers
  - Rust 버전: 1.65 이상

### 테스트 토폴로지

```
[트래픽 발생기] --- [Swift-Guard 장비] --- [목적지 서버]
    (pktgen)           (DUT)             (Traffic Sink)
```

## 2. 성능 벤치마크 시나리오

### 2.1 기본 처리량 테스트

- **목적**: Swift-Guard의 패킷 처리 성능 측정
- **지표**: 초당 패킷 수(PPS), 처리량(Gbps), CPU 사용률

```bash
#!/bin/bash
# basic_throughput_test.sh

# 테스트 설정
INTERFACE="enp1s0"
DURATION=60  # 초 단위 테스트 시간
TEST_SIZES=(64 128 512 1024 1518)  # 패킷 크기 목록

# XDP 프로그램 로드
echo "Loading XDP program..."
sudo ./target/release/xdp-filter attach $INTERFACE --mode driver

# 통계 수집 도구 시작
echo "Starting statistics collection..."
./target/release/xdp-filter stats --interval 1 > throughput_results.csv &
STATS_PID=$!

# pktgen 설정 및 실행
for SIZE in "${TEST_SIZES[@]}"; do
    echo "Testing with packet size: $SIZE bytes"
    sudo pktgen_setup.sh --interface $INTERFACE --size $SIZE --duration $DURATION --output "pktgen_${SIZE}bytes.log"
    sleep 5  # 시스템 안정화를 위한 대기 시간
done

# 통계 수집 도구 종료
kill $STATS_PID

# XDP 프로그램 언로드
echo "Unloading XDP program..."
sudo ./target/release/xdp-filter detach $INTERFACE

echo "Test completed. Results saved to throughput_results.csv and pktgen_*.log files."
```

### 2.2 규칙 스케일링 테스트

- **목적**: 필터링 규칙 수에 따른 성능 영향 측정
- **지표**: 규칙 수에 따른 처리량, 지연 시간 증가

```bash
#!/bin/bash
# rule_scaling_test.sh

# 테스트 설정
INTERFACE="enp1s0"
RULE_COUNTS=(10 100 1000 5000 10000)
PACKET_SIZE=512  # 고정 패킷 크기
DURATION=30

# XDP 프로그램 로드
echo "Loading XDP program..."
sudo ./target/release/xdp-filter attach $INTERFACE --mode driver

# 각 규칙 수에 대해 테스트
for COUNT in "${RULE_COUNTS[@]}"; do
    echo "Testing with $COUNT rules..."
    
    # 규칙 생성 스크립트 실행
    ./generate_rules.sh $COUNT
    
    # 통계 수집 시작
    ./target/release/xdp-filter stats --interval 1 > "rules_${COUNT}_stats.csv" &
    STATS_PID=$!
    
    # 트래픽 발생
    sudo pktgen_setup.sh --interface $INTERFACE --size $PACKET_SIZE --duration $DURATION --output "pktgen_rules_${COUNT}.log"
    
    # 통계 수집 종료
    kill $STATS_PID
    
    # 규칙 삭제
    ./clean_rules.sh
    
    sleep 5  # 시스템 안정화
done

# XDP 프로그램 언로드
echo "Unloading XDP program..."
sudo ./target/release/xdp-filter detach $INTERFACE

echo "Test completed. Results saved to rules_*_stats.csv and pktgen_rules_*.log files."
```

### 2.3 WASM 모듈 오버헤드 테스트

- **목적**: WASM 기반 검사 모듈의 성능 영향 측정
- **지표**: WASM 모듈 유무에 따른 처리량, 지연 시간 차이

```bash
#!/bin/bash
# wasm_overhead_test.sh

# 테스트 설정
INTERFACE="enp1s0"
WASM_MODULES=("null_module.wasm" "basic_inspector.wasm" "complex_inspector.wasm")
PACKET_SIZE=512
DURATION=30

# XDP 프로그램 로드
echo "Loading XDP program..."
sudo ./target/release/xdp-filter attach $INTERFACE --mode driver

# 기본 XDP 성능 측정 (WASM 없음)
echo "Testing with no WASM module..."
./target/release/xdp-filter stats --interval 1 > "wasm_none_stats.csv" &
STATS_PID=$!
sudo pktgen_setup.sh --interface $INTERFACE --size $PACKET_SIZE --duration $DURATION --output "pktgen_wasm_none.log"
kill $STATS_PID
sleep 5

# 각 WASM 모듈에 대해 테스트
for MODULE in "${WASM_MODULES[@]}"; do
    echo "Testing with WASM module: $MODULE"
    
    # WASM 모듈 로드
    ./load_wasm_module.sh $MODULE
    
    # 통계 수집 시작
    ./target/release/xdp-filter stats --interval 1 > "wasm_${MODULE}_stats.csv" &
    STATS_PID=$!
    
    # 트래픽 발생
    sudo pktgen_setup.sh --interface $INTERFACE --size $PACKET_SIZE --duration $DURATION --output "pktgen_wasm_${MODULE}.log"
    
    # 통계 수집 종료
    kill $STATS_PID
    
    # WASM 모듈 언로드
    ./unload_wasm_module.sh $MODULE
    
    sleep 5  # 시스템 안정화
done

# XDP 프로그램 언로드
echo "Unloading XDP program..."
sudo ./target/release/xdp-filter detach $INTERFACE

echo "Test completed. Results saved to wasm_*_stats.csv and pktgen_wasm_*.log files."
```

## 3. 보안 효과성 테스트

### 3.1 공격 탐지 및 차단 테스트

- **목적**: Swift-Guard의 보안 효과성 검증
- **지표**: 탐지율, 오탐률, 차단 지연 시간

```bash
#!/bin/bash
# security_effectiveness_test.sh

# 테스트 설정
INTERFACE="enp1s0"
ATTACK_TYPES=("syn_flood" "http_injection" "port_scan" "malformed_packet")
WASM_MODULE="security_inspector.wasm"

# XDP 프로그램 및 보안 WASM 모듈 로드
echo "Loading XDP program and security WASM module..."
sudo ./target/release/xdp-filter attach $INTERFACE --mode driver
./load_wasm_module.sh $WASM_MODULE

# 각 공격 유형에 대해 테스트
for ATTACK in "${ATTACK_TYPES[@]}"; do
    echo "Testing against attack: $ATTACK"
    
    # 로깅 시작
    ./capture_logs.sh "security_${ATTACK}.log" &
    LOG_PID=$!
    
    # 공격 트래픽 생성
    ./generate_attack.sh $ATTACK
    
    # 로깅 종료
    sleep 5
    kill $LOG_PID
    
    # 결과 수집
    ./analyze_security_logs.sh "security_${ATTACK}.log" > "security_results_${ATTACK}.txt"
    
    sleep 5  # 시스템 안정화
done

# 모듈 및 XDP 프로그램 언로드
echo "Unloading WASM module and XDP program..."
./unload_wasm_module.sh $WASM_MODULE
sudo ./target/release/xdp-filter detach $INTERFACE

echo "Test completed. Results saved to security_results_*.txt files."
```

## 4. 데이터 분석 및 그래프 생성

### 4.1 성능 데이터 분석 스크립트

```python
#!/usr/bin/env python3
# analyze_performance.py

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

# 스타일 설정
sns.set(style="whitegrid")
plt.rcParams.update({'font.size': 12})

def analyze_basic_throughput():
    """기본 처리량 테스트 결과 분석"""
    print("Analyzing basic throughput results...")
    
    # 결과 데이터 로드
    df = pd.read_csv('throughput_results.csv')
    
    # 처리량 그래프
    plt.figure(figsize=(12, 6))
    
    plt.subplot(1, 2, 1)
    plt.plot(df['packet_size'], df['pps'], 'o-', linewidth=2)
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Packets Per Second (PPS)')
    plt.title('Packet Throughput vs Packet Size')
    plt.grid(True)
    
    plt.subplot(1, 2, 2)
    plt.plot(df['packet_size'], df['gbps'], 'o-', linewidth=2, color='orange')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Throughput (Gbps)')
    plt.title('Bandwidth vs Packet Size')
    plt.grid(True)
    
    plt.tight_layout()
    plt.savefig('basic_throughput.png', dpi=300)
    plt.close()

def analyze_rule_scaling():
    """규칙 스케일링 테스트 결과 분석"""
    print("Analyzing rule scaling results...")
    
    rule_counts = [10, 100, 1000, 5000, 10000]
    pps_values = []
    latency_values = []
    
    # 각 규칙 수에 대한 결과 로드
    for count in rule_counts:
        df = pd.read_csv(f'rules_{count}_stats.csv')
        pps_values.append(df['pps'].mean())
        
        # 지연 시간 데이터 로드 (별도 파일)
        latency_df = pd.read_csv(f'pktgen_rules_{count}.log', delimiter='\s+')
        latency_values.append(latency_df['latency_us'].mean())
    
    # 그래프 생성
    plt.figure(figsize=(12, 6))
    
    plt.subplot(1, 2, 1)
    plt.plot(rule_counts, pps_values, 'o-', linewidth=2)
    plt.xlabel('Number of Rules')
    plt.ylabel('Packets Per Second (PPS)')
    plt.title('Throughput vs Rule Count')
    plt.grid(True)
    plt.xscale('log')
    
    plt.subplot(1, 2, 2)
    plt.plot(rule_counts, latency_values, 'o-', linewidth=2, color='green')
    plt.xlabel('Number of Rules')
    plt.ylabel('Latency (μs)')
    plt.title('Latency vs Rule Count')
    plt.grid(True)
    plt.xscale('log')
    
    plt.tight_layout()
    plt.savefig('rule_scaling.png', dpi=300)
    plt.close()

def analyze_wasm_overhead():
    """WASM 모듈 오버헤드 테스트 결과 분석"""
    print("Analyzing WASM overhead results...")
    
    modules = ['none', 'null_module.wasm', 'basic_inspector.wasm', 'complex_inspector.wasm']
    pps_values = []
    cpu_values = []
    
    # 각 WASM 모듈에 대한 결과 로드
    for module in modules:
        df = pd.read_csv(f'wasm_{module}_stats.csv')
        pps_values.append(df['pps'].mean())
        cpu_values.append(df['cpu_util'].mean())
    
    # 모듈 이름 간소화
    module_names = ['No WASM', 'Null Module', 'Basic Module', 'Complex Module']
    
    # 그래프 생성
    plt.figure(figsize=(12, 6))
    
    plt.subplot(1, 2, 1)
    bars = plt.bar(module_names, pps_values, color='skyblue')
    plt.xlabel('WASM Module Type')
    plt.ylabel('Packets Per Second (PPS)')
    plt.title('Throughput vs WASM Module Type')
    plt.xticks(rotation=45)
    plt.grid(axis='y')
    
    # 성능 오버헤드 백분율 표시
    baseline = pps_values[0]
    for i, bar in enumerate(bars):
        if i > 0:  # 첫 번째 바는 기준점
            overhead = ((baseline - pps_values[i]) / baseline) * 100
            plt.text(bar.get_x() + bar.get_width()/2., 
                     bar.get_height() + 0.05 * max(pps_values),
                     f'{overhead:.1f}%',
                     ha='center', va='bottom', rotation=0)
    
    plt.subplot(1, 2, 2)
    plt.bar(module_names, cpu_values, color='salmon')
    plt.xlabel('WASM Module Type')
    plt.ylabel('CPU Utilization (%)')
    plt.title('CPU Usage vs WASM Module Type')
    plt.xticks(rotation=45)
    plt.grid(axis='y')
    
    plt.tight_layout()
    plt.savefig('wasm_overhead.png', dpi=300)
    plt.close()

def analyze_security_effectiveness():
    """보안 효과성 테스트 결과 분석"""
    print("Analyzing security effectiveness results...")
    
    attack_types = ['syn_flood', 'http_injection', 'port_scan', 'malformed_packet']
    detection_rates = []
    false_positive_rates = []
    reaction_times = []
    
    # 각 공격 유형에 대한 결과 로드
    for attack in attack_types:
        with open(f'security_results_{attack}.txt', 'r') as f:
            lines = f.readlines()
            for line in lines:
                if 'Detection Rate:' in line:
                    detection_rates.append(float(line.split(':')[1].strip().rstrip('%')))
                elif 'False Positive Rate:' in line:
                    false_positive_rates.append(float(line.split(':')[1].strip().rstrip('%')))
                elif 'Average Reaction Time:' in line:
                    reaction_times.append(float(line.split(':')[1].strip().rstrip('ms')))
    
    # 간단한 공격 유형 이름
    attack_names = ['SYN Flood', 'HTTP Injection', 'Port Scan', 'Malformed Packet']
    
    # 그래프 생성
    plt.figure(figsize=(15, 6))
    
    plt.subplot(1, 3, 1)
    plt.bar(attack_names, detection_rates, color='green')
    plt.xlabel('Attack Type')
    plt.ylabel('Detection Rate (%)')
    plt.title('Attack Detection Rate')
    plt.xticks(rotation=45)
    plt.ylim(0, 100)
    plt.grid(axis='y')
    
    plt.subplot(1, 3, 2)
    plt.bar(attack_names, false_positive_rates, color='red')
    plt.xlabel('Attack Type')
    plt.ylabel('False Positive Rate (%)')
    plt.title('False Positive Rate')
    plt.xticks(rotation=45)
    plt.ylim(0, 20)  # 낮은 값이 좋으므로 스케일 조정
    plt.grid(axis='y')
    
    plt.subplot(1, 3, 3)
    plt.bar(attack_names, reaction_times, color='blue')
    plt.xlabel('Attack Type')
    plt.ylabel('Reaction Time (ms)')
    plt.title('Average Reaction Time')
    plt.xticks(rotation=45)
    plt.grid(axis='y')
    
    plt.tight_layout()
    plt.savefig('security_effectiveness.png', dpi=300)
    plt.close()

def create_comparison_chart():
    """기존 솔루션과의 비교 차트 생성"""
    print("Creating comparison chart...")
    
    solutions = ['Swift-Guard', 'Traditional FW', 'DPDK-based', 'XDP-vanilla']
    metrics = ['Throughput (Gbps)', 'Latency (μs)', 'CPU Usage (%)', 'Features']
    
    # 예시 데이터 (실제 테스트 결과로 대체 필요)
    data = {
        'Throughput (Gbps)': [9.8, 3.2, 8.5, 7.1],
        'Latency (μs)': [4.2, 85.3, 10.5, 8.7],
        'CPU Usage (%)': [35, 75, 60, 45],
        'Features': [0.9, 0.7, 0.5, 0.4]  # 표준화된 기능 점수 (0-1)
    }
    
    # 레이더 차트 생성
    categories = metrics
    N = len(categories)
    
    # 데이터 표준화 (0-1 스케일)
    normalized_data = {}
    for metric in metrics:
        if metric != 'Features':  # 이미 표준화된 기능 점수는 제외
            values = data[metric]
            if metric == 'Latency (μs)':  # 지연 시간은 낮을수록 좋음
                normalized_data[metric] = [1 - (v - min(values)) / (max(values) - min(values)) for v in values]
            else:  # 처리량과 기능은 높을수록 좋음
                normalized_data[metric] = [(v - min(values)) / (max(values) - min(values)) for v in values]
        else:
            normalized_data[metric] = data[metric]
    
    # 각 솔루션을 하나의 데이터 포인트로 조정
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]  # 폐곡선을 위한 반복
    
    plt.figure(figsize=(10, 8))
    ax = plt.subplot(111, polar=True)
    
    for i, solution in enumerate(solutions):
        values = [normalized_data[metric][i] for metric in metrics]
        values += values[:1]  # 폐곡선을 위한 반복
        
        ax.plot(angles, values, linewidth=2, label=solution)
        ax.fill(angles, values, alpha=0.1)
    
    # 차트 설정
    plt.xticks(angles[:-1], categories)
    ax.set_rlabel_position(0)
    plt.yticks([0.25, 0.5, 0.75], ["0.25", "0.5", "0.75"], color="grey", size=8)
    plt.ylim(0, 1)
    
    plt.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))
    plt.title('Comparison of Network Security Solutions', size=15, y=1.1)
    
    plt.tight_layout()
    plt.savefig('solution_comparison.png', dpi=300)
    plt.close()

if __name__ == "__main__":
    # 모든 분석 실행
    analyze_basic_throughput()
    analyze_rule_scaling()
    analyze_wasm_overhead()
    analyze_security_effectiveness()
    create_comparison_chart()
    
    print("Analysis completed. All graphs have been generated.")
```

## 5. SCIE 저널 투고를 위한 결과 정리

### 5.1 논문 구조

1. **Abstract**
   - Swift-Guard의 주요 개념, 혁신점, 주요 결과 요약

2. **Introduction**
   - 네트워크 보안의 현재 도전 과제
   - XDP 및 eBPF 기술의 등장과 중요성
   - WASM의 보안 애플리케이션 가능성
   - 연구 목표 및 기여점

3. **Related Work**
   - 기존 네트워크 보안 솔루션 비교
   - XDP 기반 연구 동향
   - WASM 기반 보안 애플리케이션 리뷰

4. **System Architecture**
   - Swift-Guard 아키텍처 상세 설명
   - XDP 필터링 메커니즘
   - WASM 통합 인터페이스
   - 최적화 기법

5. **Implementation**
   - 주요 구현 세부 사항
   - 핵심 알고리즘 및 데이터 구조
   - 시스템 컴포넌트 통합

6. **Evaluation**
   - 실험 환경 및 방법론
   - 성능 벤치마크 결과
   - 보안 효과성 평가
   - 기존 솔루션과의 비교

7. **Discussion**
   - 결과 분석 및 의미
   - 제한 사항 및 향후 개선 방향
   - 실제 환경 적용 시 고려 사항

8. **Conclusion**
   - 연구 요약 및 주요 발견
   - 향후 연구 방향

### 5.2 주요 실험 결과 요약 (예상)

- **처리량 성능**: 기존 네트워크 보안 솔루션 대비 3-4배 향상된 처리량
- **지연 시간**: 마이크로초 단위의 초저지연 패킷 처리 달성
- **규칙 확장성**: 10,000개 이상의 규칙을 적용해도 성능 저하 최소화
- **WASM 오버헤드**: 기본 XDP 성능 대비 10-15% 내외의 적은 오버헤드
- **보안 효과성**: 주요 네트워크 공격에 대해 95% 이상의 탐지율, 5% 미만의 오탐률

## 6. 추가 개발 및 연구 방향

1. **분산 환경 지원**:
   - Kubernetes 환경 통합
   - 다중 노드 간 정책 일관성 보장

2. **자가 적응형 보안**:
   - 머신러닝 기반 이상 탐지
   - 실시간 위협 상황에 따른 자동 정책 조정

3. **고급 WASM 보안 모듈**:
   - DPI(Deep Packet Inspection) 모듈
   - 암호화 트래픽 분석 모듈
   - IoT 프로토콜 특화 보안 모듈

4. **성능 최적화**:
   - 멀티 큐 NIC 최적화
   - NUMA 인식 리소스 할당
   - CPU 친화성 튜닝
