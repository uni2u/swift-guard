//! 텔레메트리 수집기 모듈
//! 성능 및 운영 메트릭 수집

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time;

use crate::bpf::XdpFilterSkel;
use crate::config::DaemonConfig;
//use crate::api::SystemStats;

use swift_guard::api::SystemStats;
use libbpf_rs::MapFlags;

/// 텔레메트리 수집기
//#[derive(Debug)]
pub struct TelemetryCollector {
    /// 통계 맵 참조
    stats_map: libbpf_rs::Map,
    /// 구성 정보
    config: DaemonConfig,
    /// 수집된 통계
    stats: Arc<Mutex<CollectedStats>>,
    /// 마지막 수집 시간
    last_collection: Instant,
}

/// 수집된 통계
#[derive(Debug, Clone)]
pub struct CollectedStats {
    /// 총 패킷 수
    pub total_packets: u64,
    /// 총 바이트
    pub total_bytes: u64,
    /// 초당 패킷 수
    pub packets_per_sec: u64,
    /// Mbps
    pub mbps: f64,
    /// 마지막 업데이트 시간
    pub last_update: u64,
    /// 이전 패킷 수
    prev_packets: u64,
    /// 이전 바이트
    prev_bytes: u64,
}

// Debug 구현
impl std::fmt::Debug for TelemetryCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryCollector")
            .field("config", &self.config)
            .finish()
    }
}

impl TelemetryCollector {
    /// 새로운 텔레메트리 수집기 생성
    pub fn new(skel: &XdpFilterSkel, config: &DaemonConfig) -> Result<Self> {
        // 통계 맵 획득
        let stats_map = skel.maps().stats_map()
            .ok_or_else(|| anyhow!("Failed to get stats_map"))?;
        
        Ok(Self {
            stats_map: stats_map.clone(),
            config: config.clone(),
            stats: Arc::new(Mutex::new(CollectedStats {
                total_packets: 0,
                total_bytes: 0,
                packets_per_sec: 0,
                mbps: 0.0,
                last_update: 0,
                prev_packets: 0,
                prev_bytes: 0,
            })),
            last_collection: Instant::now(),
        })
    }
    
    /// 통계 수집
    pub async fn collect_stats(&self) -> Result<()> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_collection).as_secs_f64();
        
        // 최소 간격 확인
        if elapsed < 0.1 {
            return Ok(());
        }
        
        let key = 0u32.to_le_bytes();
        
        // 맵에서 통계 읽기
//        if let Ok(value) = self.stats_map.lookup(&key, 0) {
        if let Ok(Some(value)) = self.stats_map.lookup(&key, MapFlags::empty()) {
            if value.len() >= 16 {
                // 통계 데이터 파싱
                let packets = u64::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                    value[4], value[5], value[6], value[7],
                ]);
                
                let bytes = u64::from_le_bytes([
                    value[8], value[9], value[10], value[11],
                    value[12], value[13], value[14], value[15],
                ]);
                
                // 통계 업데이트
                let mut stats = self.stats.lock()
                    .map_err(|_| anyhow!("Failed to lock stats"))?;
                
                // 초당 패킷 수 및 Mbps 계산
                let packets_diff = packets.saturating_sub(stats.prev_packets);
                let bytes_diff = bytes.saturating_sub(stats.prev_bytes);
                
                stats.packets_per_sec = (packets_diff as f64 / elapsed) as u64;
                stats.mbps = (bytes_diff as f64 * 8.0 / elapsed) / 1_000_000.0;
                
                // 총계 업데이트
                stats.total_packets = packets;
                stats.total_bytes = bytes;
                stats.last_update = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| anyhow!("Failed to get system time"))?
                    .as_secs();
                
                // 이전 값 저장
                stats.prev_packets = packets;
                stats.prev_bytes = bytes;
                
                // 로그 기록 (구성에서 활성화된 경우)
                if self.config.telemetry.log_stats {
                    debug!("Stats - Packets: {}, Bytes: {}, PPS: {}, Mbps: {:.2}",
                        packets, bytes, stats.packets_per_sec, stats.mbps);
                }
            }
        }
        
        Ok(())
    }
    
    /// 현재 통계 획득
    pub fn get_stats(&self) -> Result<SystemStats> {
        let stats = self.stats.lock()
            .map_err(|_| anyhow!("Failed to lock stats"))?;
        
        Ok(SystemStats {
            total_packets: stats.total_packets,
            total_bytes: stats.total_bytes,
            packets_per_sec: stats.packets_per_sec,
            mbps: stats.mbps,
        })
    }
}
