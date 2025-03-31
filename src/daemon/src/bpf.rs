// src/daemon/src/bpf.rs
use anyhow::{anyhow, Context, Result};
use libbpf_rs::{Map, Object, ObjectBuilder, Program};
use log::{debug, error, info};
use std::path::Path;
use std::process::Command;

pub struct XdpFilterSkel {
    pub obj: Object,
}

impl XdpFilterSkel {
    pub fn builder() -> XdpFilterSkelBuilder {
        XdpFilterSkelBuilder {
            obj_path: None,
        }
    }

    pub fn maps(&self) -> XdpFilterMaps {
        XdpFilterMaps {
            obj: &self.obj,
        }
    }

    pub fn progs(&self) -> XdpFilterProgs {
        XdpFilterProgs {
            obj: &self.obj,
        }
    }
}

pub struct XdpFilterSkelBuilder {
    obj_path: Option<String>,
}

impl XdpFilterSkelBuilder {
    pub fn obj_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.obj_path = Some(path.as_ref().to_string_lossy().to_string());
        self
    }

    pub fn open(self) -> Result<XdpFilterSkel> {
        let mut builder = ObjectBuilder::default();
        let path = self.obj_path.ok_or_else(|| anyhow!("No Object file path provided"))?;
        let object = builder.open_file(path)?;

        Ok(XdpFilterSkel {
            obj: object.load().expect("Failed to load object"),
        })
    }
}

pub struct XdpFilterMaps<'a> {
    obj: &'a Object,
}

impl<'a> XdpFilterMaps<'a> {
    pub fn filter_rules(&self) -> Option<&Map> {
        self.obj.map("filter_rules")
    }
    
    pub fn redirect_map(&self) -> Option<&Map> {
        self.obj.map("redirect_map")
    }
    
    pub fn stats_map(&self) -> Option<&Map> {
        self.obj.map("stats_map")
    }
}

pub struct XdpFilterProgs<'a> {
    obj: &'a Object,
}

impl<'a> XdpFilterProgs<'a> {
    pub fn xdp_filter_func(&self) -> Option<&Program> {
        self.obj.prog("xdp_filter_func")
    }
}

/// XDP 모드 열거형
#[derive(Debug, Clone, Copy)]
pub enum XdpMode {
    Driver = 0,  // 드라이버/네이티브 모드
    Generic = 1, // SKB 기반 제네릭 모드
    Offload = 2, // 하드웨어 오프로드 모드
}

/// XDP 프로그램 로드
pub fn load_xdp_program(obj_path: &Path, interface: &str) -> Result<()> {
    // BPF 오브젝트 파일 존재 확인
    if !obj_path.exists() {
        return Err(anyhow!("BPF 오브젝트 파일이 존재하지 않습니다: {}", obj_path.display()));
    }

    // 인터페이스 존재 확인
    check_interface_exists(interface)?;

    // ip 명령으로 XDP 프로그램 로드
    let status = Command::new("ip")
        .args(&["link", "set", "dev", interface, "xdp", "obj", 
               obj_path.to_str().unwrap(), "sec", "xdp"])
        .status()
        .context(format!("인터페이스 {}에 XDP 프로그램 로드 실패", interface))?;

    if !status.success() {
        return Err(anyhow!("인터페이스 {}에 XDP 프로그램 로드 실패", interface));
    }

    info!("인터페이스 {}에 XDP 프로그램이 로드되었습니다", interface);
    Ok(())
}

/// XDP 프로그램 언로드
pub fn unload_xdp_program(interface: &str) -> Result<()> {
    // 인터페이스 존재 확인
    check_interface_exists(interface)?;

    // ip 명령으로 XDP 프로그램 언로드
    let status = Command::new("ip")
        .args(&["link", "set", "dev", interface, "xdp", "off"])
        .status()
        .context(format!("인터페이스 {}에서 XDP 프로그램 언로드 실패", interface))?;

    if !status.success() {
        return Err(anyhow!("인터페이스 {}에서 XDP 프로그램 언로드 실패", interface));
    }

    info!("인터페이스 {}에서 XDP 프로그램이 언로드되었습니다", interface);
    Ok(())
}

/// 인터페이스 존재 확인
fn check_interface_exists(interface: &str) -> Result<()> {
    let output = Command::new("ip")
        .args(&["link", "show", "dev", interface])
        .output()
        .context(format!("인터페이스 {} 확인 실패", interface))?;

    if !output.status.success() {
        return Err(anyhow!("인터페이스 {}가 존재하지 않습니다", interface));
    }

    Ok(())
}