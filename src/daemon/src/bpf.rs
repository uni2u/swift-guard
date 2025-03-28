// src/daemon/src/bpf.rs
use anyhow::{anyhow, Context, Result};
//use libbpf_rs::{MapFlags, Object, ObjectBuilder, Program, ProgramAttachTarget, ProgramAttachType, ProgramType};
use libbpf_rs::{MapFlags, Map, Object, ObjectBuilder, Program, ProgramType};
//use log::{debug, error, info};
use log::info;
use std::path::Path;

pub struct XdpFilterSkel {
    obj: Object,
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
        /*
        match self.obj.map("filter_rules") {
            Ok(map) => Some(map),
            Err(_) => None,
        }
        */
        self.obj.map("filter_rules")
    }
    
    pub fn redirect_map(&self) -> Option<&Map> {
        /*
        match self.obj.map("redirect_map") {
            Ok(map) => Some(map),
            Err(_) => None,
        }
        */
        self.obj.map("redirect_map")
    }
    
    pub fn stats_map(&self) -> Option<&Map> {
        /*
        match self.obj.map("stats_map") {
            Ok(map) => Some(map),
            Err(_) => None,
        }
        */
        self.obj.map("stats_map")
    }
}

/*
impl<'a> XdpFilterMaps<'a> {
    pub fn filter_rules(&self) -> Option<libbpf_rs::Map> {
        self.obj.map("filter_rules").ok()
    }

    pub fn redirect_map(&self) -> Option<libbpf_rs::Map> {
        self.obj.map("redirect_map").ok()
    }

    pub fn stats_map(&self) -> Option<libbpf_rs::Map> {
        self.obj.map("stats_map").ok()
    }
}
*/

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

/// 
pub fn attach_xdp_program(prog: &mut Program, interface: &str, mode: XdpMode) -> Result<()> {
    // 인터페이스 인덱스 가져오기
    let if_index = nix::net::if_::if_nametoindex(interface)
        .context(format!("Failed to get interface index for {}", interface))?;

    // ProgramType 비교 제거 (PartialEq 미구현)
    /*
    if prog.prog_type() != ProgramType::Xdp {
        return Err(anyhow!("Program is not an XDP program"));
    }
    */

    // 인수 하나만 전달
    prog.attach_xdp(if_index as i32)
        .context(format!("Failed to attach XDP program to interface {}", interface))?;

    info!("XDP program attached to {} in {:?} mode", interface, mode);
    Ok(())
}

/*
/// XDP 프로그램을 네트워크 인터페이스에 연결
pub fn attach_xdp_program(prog: &Program, interface: &str, mode: XdpMode, force: bool) -> Result<()> {
    // 인터페이스 인덱스 가져오기
    let if_index = nix::net::if_::if_nametoindex(interface)
        .context(format!("Failed to get interface index for {}", interface))?;
    
    // 프로그램 타입 확인
    if prog.prog_type() != ProgramType::Xdp {
        return Err(anyhow!("Program is not an XDP program"));
    }

    // XDP 플래그 설정
    let flags = match mode {
        XdpMode::Driver => 0, // XDP_FLAGS_DRV_MODE
        XdpMode::Generic => 2, // XDP_FLAGS_SKB_MODE
        XdpMode::Offload => 4, // XDP_FLAGS_HW_MODE
    };

    // 인터페이스에 XDP 프로그램 연결
    prog.attach_xdp(if_index as i32, flags)
        .context(format!("Failed to attach XDP program to interface {}", interface))?;

    info!("XDP program attached to {} in {:?} mode", interface, mode);
    Ok(())
}
*/

/// XDP 프로그램을 네트워크 인터페이스에서 분리
pub fn detach_xdp_program(interface: &str) -> Result<()> {
    // 인터페이스 인덱스 가져오기
    let if_index = nix::net::if_::if_nametoindex(interface)
        .context(format!("Failed to get interface index for {}", interface))?;
    
    // XDP 프로그램 분리
//    libbpf_rs::Xdp::detach(if_index as i32, 0)
//    Program::detach_xdp(if_index as i32)
//        .context(format!("Failed to detach XDP program from interface {}", interface))?;

    let status = std::process::Command::new("ip")
        .args(&["link","set","dev",interface,"xdp","off"])
        .status()
        .context(format!("Failed to execute ip command to detach XDP from {}", interface))?;

    if !status.success() {
        return Err(anyhow!("Failed to detach XDP program from interface {}", interface));
    }

    info!("XDP program detached from {}", interface);
    Ok(())
}

