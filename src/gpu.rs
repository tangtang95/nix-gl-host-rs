use std::{fmt::Display, fs};

#[derive(Debug, Clone)]
pub(crate) enum GpuVendor {
    Amd,
    Nvidia,
    Unsupported(String),
}

impl TryFrom<String> for GpuVendor {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "amd" => Ok(GpuVendor::Amd),
            "nvidia" => Ok(GpuVendor::Nvidia),
            _ => Err(anyhow::anyhow!("Invalid gpu vendor"))
        }
    }
}

impl Display for GpuVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuVendor::Amd => f.write_str("Amd"),
            GpuVendor::Nvidia => f.write_str("Nvidia"),
            GpuVendor::Unsupported(_) => f.write_str("Unsupported GPU"),
        }
    }
}

pub(crate) fn detect_gpu_vendor() -> Option<GpuVendor> {
    let vendor_path = "/sys/class/drm/card0/device/vendor";
    if let Ok(vendor_id) = fs::read_to_string(vendor_path) {
        match vendor_id.trim() {
            "0x1002" => Some(GpuVendor::Amd),
            "0x10DE" => Some(GpuVendor::Nvidia),
            id => Some(GpuVendor::Unsupported(id.to_string())),
        }
    } else {
        None
    }
}
