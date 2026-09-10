use std::path::Path;

pub struct TunHelper;

impl TunHelper {
    pub fn is_tun_supported() -> bool {
        Path::new("/dev/net/tun").exists()
    }

    pub fn has_pkexec() -> bool {
        Path::new("/usr/bin/pkexec").is_file() || Path::new("/bin/pkexec").is_file()
    }

    pub fn unavailable_reason() -> Option<&'static str> {
        if !Self::is_tun_supported() {
            return Some("TUN device (/dev/net/tun) is not available");
        }
        if unsafe { libc::geteuid() } != 0 && !Self::has_pkexec() {
            return Some("pkexec is required to create a TUN interface");
        }
        None
    }
}
