//! 텔레메트리 수집기 모듈
//! 성능 및 운영 메트릭 수집
//!
//! BPF 맵을 직접 참조하지 않는다. 호출자(main 의 텔레메트리 루프)가
//! `MapManager::get_stats()` 로 읽은 합계를 `collect_stats` 에 넘긴다.

use anyhow::{anyhow, Result};
use log::debug;
use std::sync::Mutex;
use std::time::Instant;

use crate::config::DaemonConfig;

/// 텔레메트리 수집기
#[derive(Debug)]
pub struct TelemetryCollector {
    /// 구성 정보
    config: DaemonConfig,
    /// 수집된 통계
    stats: Mutex<CollectedStats>,
}

/// 수집된 통계
#[derive(Debug, Clone)]
pub struct CollectedStats {
    /// 총 패킷 수 (마지막 수집 시점)
    pub total_packets: u64,
    /// 총 바이트 (마지막 수집 시점)
    pub total_bytes: u64,
    /// 초당 패킷 수
    pub packets_per_sec: u64,
    /// Mbps
    pub mbps: f64,
    /// 마지막 업데이트 시간 (UNIX epoch 초)
    pub last_update: u64,
    /// 마지막 수집 시각 (None = 아직 수집 전)
    last_collection: Option<Instant>,
}

impl TelemetryCollector {
    /// 새로운 텔레메트리 수집기 생성
    pub fn new(config: &DaemonConfig) -> Self {
        Self {
            config: config.clone(),
            stats: Mutex::new(CollectedStats {
                total_packets: 0,
                total_bytes: 0,
                packets_per_sec: 0,
                mbps: 0.0,
                last_update: 0,
                last_collection: None,
            }),
        }
    }

    /// 통계 수집 (동기). totals = (packets, bytes) 누적 합계.
    pub fn collect_stats(&self, totals: (u64, u64)) -> Result<()> {
        let (packets, bytes) = totals;
        let now = Instant::now();

        let mut stats = self
            .stats
            .lock()
            .map_err(|_| anyhow!("Failed to lock stats"))?;

        if let Some(prev) = stats.last_collection {
            let elapsed = now.duration_since(prev).as_secs_f64();
            // 최소 간격 확인
            if elapsed < 0.1 {
                return Ok(());
            }
            let packets_diff = packets.saturating_sub(stats.total_packets);
            let bytes_diff = bytes.saturating_sub(stats.total_bytes);
            stats.packets_per_sec = (packets_diff as f64 / elapsed) as u64;
            stats.mbps = (bytes_diff as f64 * 8.0 / elapsed) / 1_000_000.0;
        }

        stats.total_packets = packets;
        stats.total_bytes = bytes;
        stats.last_update = swift_guard::utils::current_time_secs();
        stats.last_collection = Some(now);

        if self.config.telemetry.log_stats {
            debug!(
                "Stats - Packets: {}, Bytes: {}, PPS: {}, Mbps: {:.2}",
                packets, bytes, stats.packets_per_sec, stats.mbps
            );
        }

        Ok(())
    }

    /// 마지막으로 계산된 (packets_per_sec, mbps)
    pub fn rates(&self) -> Result<(u64, f64)> {
        let stats = self
            .stats
            .lock()
            .map_err(|_| anyhow!("Failed to lock stats"))?;
        Ok((stats.packets_per_sec, stats.mbps))
    }
}
