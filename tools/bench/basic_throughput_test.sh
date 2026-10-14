#!/bin/bash
# Swift-Guard 기본 처리량 테스트 스크립트

set -e

# 기본 설정
INTERFACE=""
DURATION=60
PACKET_SIZES=(64 128 512 1024 1518)
OUTPUT_DIR="./results"
PKTGEN_CONFIG="./tools/bench/pktgen_config.lua"

# 사용법 표시
show_usage() {
    echo "Usage: $0 --interface <INTERFACE> [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --interface INTERFACE  Network interface to use for testing"
    echo "  --duration SECONDS     Test duration in seconds (default: 60)"
    echo "  --packet-sizes SIZES   Comma-separated list of packet sizes to test (default: 64,128,512,1024,1518)"
    echo "  --output-dir DIR       Output directory for results (default: ./results)"
    echo "  --help                 Show this help message"
    exit 1
}

# 인수 파싱
while [[ $# -gt 0 ]]; do
    case $1 in
        --interface)
            INTERFACE="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --packet-sizes)
            IFS=',' read -r -a PACKET_SIZES <<< "$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help)
            show_usage
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            ;;
    esac
done

# 인터페이스 필수 인수 확인
if [ -z "$INTERFACE" ]; then
    echo "Error: --interface is required"
    show_usage
fi

# 인터페이스 존재 확인
if ! ip link show dev "$INTERFACE" &>/dev/null; then
    echo "Error: Interface $INTERFACE does not exist"
    exit 1
fi

# 루트 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# 출력 디렉토리 생성
mkdir -p "$OUTPUT_DIR"

# 결과 파일 헤더 작성
RESULTS_CSV="$OUTPUT_DIR/throughput_results.csv"
echo "packet_size,pps,gbps,cpu_util,memory_mb,duration_sec" > "$RESULTS_CSV"

# 테스트 실행 함수
run_test() {
    local size=$1
    local output_file="$OUTPUT_DIR/pktgen_${size}bytes.log"
    
    echo "========================================="
    echo "Testing with packet size: $size bytes"
    echo "Duration: $DURATION seconds"
    echo "Output: $output_file"
    echo "========================================="
    
    # XDP 프로그램 로드
    echo "Loading XDP program to $INTERFACE..."
    ./target/release/xdp-filter attach "$INTERFACE" --mode driver
    
    # 통계 수집 시작
    echo "Starting statistics collection..."
    ./target/release/xdp-filter stats --interval 1 > "$OUTPUT_DIR/stats_${size}bytes.log" &
    STATS_PID=$!
    
    # CPU 모니터링 시작
    mpstat 1 > "$OUTPUT_DIR/cpu_${size}bytes.log" &
    CPU_PID=$!
    
    # 메모리 모니터링 시작
    vmstat 1 > "$OUTPUT_DIR/mem_${size}bytes.log" &
    MEM_PID=$!
    
    # pktgen 설정 생성
    cat > "$PKTGEN_CONFIG" << EOF
-- Pktgen configuration for Swift-Guard throughput test
-- Packet size: $size bytes

local DST_MAC = "11:22:33:44:55:66" -- Destination MAC address
local SRC_MAC = "aa:bb:cc:dd:ee:ff" -- Source MAC address
local DST_IP = "192.168.1.1"        -- Destination IP address
local SRC_IP = "192.168.1.2"        -- Source IP address
local DST_PORT = 80                 -- Destination port
local SRC_PORT = 12345              -- Source port
local PKT_SIZE = $size              -- Packet size in bytes

function configure(parser)
    parser:config_ethdev("--no-promisc", false)
end

function master(args)
    -- Create the packet to be transmitted
    local pkt = Packet.new(PKT_SIZE)
    pkt:eth(SRC_MAC, DST_MAC)
    pkt:ip4(SRC_IP, DST_IP)
    pkt:tcp(SRC_PORT, DST_PORT)
    pkt:fill("payload", PKT_SIZE - pkt:getSize())
    
    -- Configure transmission settings
    local mem = Memory.createMemPool()
    local bufs = mem:bufArray()
    local queue = device.get(args.dev):txQueue(0)
    
    -- Test duration
    local duration = $DURATION
    local counter = 0
    local startTime = moongen.getTime()
    local lastPrint = startTime
    local lastCounter = 0
    
    -- Generate packets as fast as possible
    while moongen.getTime() < startTime + duration do
        bufs:alloc(PKT_SIZE)
        for i, buf in ipairs(bufs) do
            local pkt = buf:getUdpPacket()
            pkt:fill{ 
                ethSrc = SRC_MAC, 
                ethDst = DST_MAC,
                ip4Src = SRC_IP,
                ip4Dst = DST_IP,
                udpSrc = SRC_PORT,
                udpDst = DST_PORT,
                pktLength = PKT_SIZE
            }
        end
        counter = counter + bufs:size()
        queue:send(bufs)
        
        -- Print stats every second
        local time = moongen.getTime()
        if time - lastPrint > 1 then
            local mpps = (counter - lastCounter) / (time - lastPrint) / 10^6
            printf("Sent %d packets, current rate: %.2f Mpps, %.2f Gbit/s", 
                  counter, mpps, mpps * PKT_SIZE * 8 / 10^9)
            lastPrint = time
            lastCounter = counter
        end
    end
    
    -- Print final stats
    local totalTime = moongen.getTime() - startTime
    printf("Sent %d packets in %.2f seconds", counter, totalTime)
    printf("Average rate: %.2f Mpps, %.2f Gbit/s", 
           counter / totalTime / 10^6, 
           counter * PKT_SIZE * 8 / totalTime / 10^9)
end
EOF
    
    # pktgen 실행
    echo "Starting packet generation with MoonGen/pktgen..."
    if command -v moongen &> /dev/null; then
        moongen "$PKTGEN_CONFIG" --dev "$INTERFACE" > "$output_file" 2>&1
    elif command -v pktgen-dpdk &> /dev/null; then
        # pktgen-dpdk를 사용한 대체 방법
        echo "MoonGen not found, using pktgen-dpdk instead"
        pktgen-dpdk -l 0-3 -n 4 -- -T -P -m "[1:3].0" -f "$output_file" &
        PKTGEN_PID=$!
        sleep 2
        
        # pktgen 명령 전송
        echo "set 0 size $size" | nc -U /tmp/pktgen.sock
        echo "set 0 rate 100" | nc -U /tmp/pktgen.sock
        echo "set 0 count $((DURATION * 1000000))" | nc -U /tmp/pktgen.sock
        echo "start 0" | nc -U /tmp/pktgen.sock
        
        # 완료 대기
        sleep "$DURATION"
        kill $PKTGEN_PID
    else
        echo "Error: Neither MoonGen nor pktgen-dpdk found"
        # 간단한 테스트용 트래픽 생성 (iperf)
        echo "Falling back to iperf for basic traffic generation"
        iperf -s -u &
        IPERF_SERVER=$!
        iperf -c localhost -u -b 1G -l "$size" -t "$DURATION" > "$output_file" 2>&1
        kill $IPERF_SERVER
    fi
    
    # 모니터링 프로세스 종료
    kill $STATS_PID $CPU_PID $MEM_PID 2>/dev/null || true
    wait
    
    # XDP 프로그램 언로드
    echo "Unloading XDP program..."
    ./target/release/xdp-filter detach "$INTERFACE"
    
    # 결과 파싱 및 저장
    echo "Parsing results..."
    local max_pps=$(grep "packets_per_sec" "$OUTPUT_DIR/stats_${size}bytes.log" | awk '{print $2}' | sort -n | tail -1)
    local max_gbps=$(grep "mbps" "$OUTPUT_DIR/stats_${size}bytes.log" | awk '{print $2/1000}' | sort -n | tail -1)
    local avg_cpu=$(awk '/all/ {sum+=$3; count++} END {print sum/count}' "$OUTPUT_DIR/cpu_${size}bytes.log")
    local avg_mem=$(awk 'NR > 2 {sum+=$4; count++} END {print sum/count/1024}' "$OUTPUT_DIR/mem_${size}bytes.log")
    
    # 결과 저장
    echo "$size,$max_pps,$max_gbps,$avg_cpu,$avg_mem,$DURATION" >> "$RESULTS_CSV"
    
    echo "Test completed for $size bytes packet size"
    echo ""
}

# 메인 스크립트
echo "Starting Swift-Guard basic throughput test"
echo "Interface: $INTERFACE"
echo "Duration: $DURATION seconds"
echo "Packet sizes: ${PACKET_SIZES[*]}"
echo "Results will be saved to $OUTPUT_DIR"
echo ""

# 각 패킷 크기에 대해 테스트 실행
for size in "${PACKET_SIZES[@]}"; do
    run_test "$size"
    # 시스템 안정화를 위한 대기
    sleep 5
done

echo "All tests completed!"
echo "Results saved to $RESULTS_CSV"
echo ""
echo "To analyze results, run:"
echo "  python tools/analysis/analyze_performance.py"
