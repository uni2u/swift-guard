// src/daemon/src/bpf.rs
//! BPF 오브젝트 로드와 XDP attach/detach
//!
//! libbpf-rs 0.19 의 Object/Map/Program 은 raw pointer 를 가져 !Send/!Sync 이다.
//! 이 모듈의 타입은 main 태스크에서만 사용한다(tokio::spawn 금지).

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{Object, ObjectBuilder};
use log::{info, warn};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// 로드된 XDP 필터 BPF 오브젝트
pub struct XdpFilterSkel {
    pub obj: Object,
}

impl XdpFilterSkel {
    pub fn builder() -> XdpFilterSkelBuilder {
        XdpFilterSkelBuilder { obj_path: None }
    }
}

pub struct XdpFilterSkelBuilder {
    obj_path: Option<PathBuf>,
}

impl XdpFilterSkelBuilder {
    pub fn obj_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.obj_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// BPF 오브젝트를 열고 커널에 로드한다(verifier 통과 필요).
    pub fn open(self) -> Result<XdpFilterSkel> {
        let path = self
            .obj_path
            .ok_or_else(|| anyhow!("No BPF object file path provided"))?;
        if !path.exists() {
            return Err(anyhow!("BPF object file not found: {}", path.display()));
        }

        let open_obj = ObjectBuilder::default()
            .open_file(&path)
            .with_context(|| format!("Failed to open BPF object {}", path.display()))?;
        let obj = open_obj
            .load()
            .with_context(|| format!("Failed to load BPF object {} into kernel", path.display()))?;

        Ok(XdpFilterSkel { obj })
    }
}

/// 인터페이스 이름 → ifindex (`if_nametoindex`)
pub fn ifindex_of(ifname: &str) -> Result<u32> {
    nix::net::if_::if_nametoindex(ifname)
        .map_err(|e| anyhow!("unknown interface '{}': {}", ifname, e))
}

/// API mode 값(0=driver, 1=generic, 2=offload)을 XDP 모드 플래그로 변환
pub fn mode_flags(mode: Option<u32>) -> Result<u32> {
    match mode {
        None => Ok(0), // 커널 자동 선택
        Some(0) => Ok(libbpf_sys::XDP_FLAGS_DRV_MODE),
        Some(1) => Ok(libbpf_sys::XDP_FLAGS_SKB_MODE),
        Some(2) => Ok(libbpf_sys::XDP_FLAGS_HW_MODE),
        Some(m) => Err(anyhow!(
            "invalid XDP mode {} (0=driver, 1=generic, 2=offload)",
            m
        )),
    }
}

fn os_err(ret: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(-ret)
}

/// netlink 기반 XDP attach 상태 관리자.
/// netlink 로 붙인 XDP 는 프로세스가 죽어도 남으므로 종료 시 detach_all 이 필수다.
#[derive(Debug, Default)]
pub struct XdpAttachManager {
    /// ifname → attach 기록
    attached: HashMap<String, AttachedProg>,
}

/// 이 daemon 이 붙인 XDP 프로그램 기록
#[derive(Debug, Clone, Copy)]
struct AttachedProg {
    ifindex: u32,
    /// 모드 플래그 (DRV/SKB/HW 또는 0)
    mflags: u32,
    /// attach 한 프로그램 fd. detach 시 old_prog_fd 로 넘겨 일치할 때만 뗀다.
    prog_fd: i32,
}

impl XdpAttachManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// prog_fd 를 ifname 에 attach. 이미 이 daemon 이 붙인 인터페이스면
    /// force=true 일 때 detach 후 재attach, force=false 면 Err.
    pub fn attach(&mut self, prog_fd: i32, ifname: &str, mode: Option<u32>, force: bool) -> Result<()> {
        let mflags = mode_flags(mode)?;
        let ifindex = ifindex_of(ifname)?;

        if self.attached.contains_key(ifname) {
            if !force {
                return Err(anyhow!(
                    "XDP program is already attached to {} by this daemon (use --force to replace)",
                    ifname
                ));
            }
            // force: 기존 것이 외부에서 바뀌었어도(detach 실패) 아래 attach 가 덮어쓴다
            if let Err(e) = self.detach(ifname) {
                warn!("force attach {}: previous detach failed: {:#}", ifname, e);
                self.attached.remove(ifname);
            }
        }

        let mut flags = mflags;
        if !force {
            flags |= libbpf_sys::XDP_FLAGS_UPDATE_IF_NOEXIST;
        }

        let ret = unsafe {
            libbpf_sys::bpf_xdp_attach(ifindex as i32, prog_fd, flags, std::ptr::null())
        };
        if ret < 0 {
            return Err(anyhow!(
                "Failed to attach XDP program to {} (ifindex {}, flags {:#x}): {}",
                ifname,
                ifindex,
                flags,
                os_err(ret)
            ));
        }

        self.attached.insert(
            ifname.to_string(),
            AttachedProg {
                ifindex,
                mflags,
                prog_fd,
            },
        );
        info!("XDP program attached to {} (ifindex {}, flags {:#x})", ifname, ifindex, flags);
        Ok(())
    }

    /// 이 daemon 이 붙인 인터페이스에서만 detach 한다.
    /// 현재 붙어 있는 프로그램이 이 daemon 이 붙인 것과 같을 때만 뗀다
    /// (old_prog_fd 지정 → libbpf 가 XDP_FLAGS_REPLACE 를 설정, 불일치 시 커널이 EEXIST).
    pub fn detach(&mut self, ifname: &str) -> Result<()> {
        let AttachedProg {
            ifindex,
            mflags,
            prog_fd,
        } = *self
            .attached
            .get(ifname)
            .ok_or_else(|| anyhow!("XDP program is not attached to {} by this daemon", ifname))?;

        // 인터페이스가 사라졌는지 확인 (사라졌으면 커널이 이미 프로그램을 해제했다)
        if let Err(e) = ifindex_of(ifname) {
            self.attached.remove(ifname);
            return Err(e);
        }

        let opts = libbpf_sys::bpf_xdp_attach_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t,
            old_prog_fd: prog_fd,
            ..Default::default()
        };
        let ret = unsafe { libbpf_sys::bpf_xdp_detach(ifindex as i32, mflags, &opts) };
        if ret == -libc::EEXIST {
            // 외부에서 다른 XDP 프로그램으로 교체(또는 제거)됐다. 남의 프로그램은 떼지 않는다.
            self.attached.remove(ifname);
            return Err(anyhow!(
                "XDP program on {} (ifindex {}) is no longer the one attached by this daemon; \
                 leaving it in place",
                ifname,
                ifindex
            ));
        }
        if ret < 0 {
            return Err(anyhow!(
                "Failed to detach XDP program from {} (ifindex {}): {}",
                ifname,
                ifindex,
                os_err(ret)
            ));
        }

        self.attached.remove(ifname);
        info!("XDP program detached from {}", ifname);
        Ok(())
    }

    /// 붙인 모든 인터페이스에서 detach (종료 시). 실패는 로그만 남긴다.
    pub fn detach_all(&mut self) {
        let names: Vec<String> = self.attached.keys().cloned().collect();
        for name in names {
            if let Err(e) = self.detach(&name) {
                warn!("detach {} failed: {:#}", name, e);
                self.attached.remove(&name);
            }
        }
    }
}
