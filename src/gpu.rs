use std::fs;

pub(crate) enum GpuVendor {
    Amd,
    Nvidia,
    Unsupported(String),
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
