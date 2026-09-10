const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

fn humanize(bytes: u64) -> (f64, &'static str) {
    let mut value = bytes as f64;
    let mut unit_index = 0;
    while value >= 1024.0 && unit_index + 1 < UNITS.len() {
        value /= 1024.0;
        unit_index += 1;
    }
    (value, UNITS[unit_index])
}

pub fn format_bytes(bytes: u64) -> String {
    let (value, unit) = humanize(bytes);
    if unit == "B" {
        format!("{} {}", bytes, unit)
    } else {
        format!("{:.2} {}", value, unit)
    }
}

pub fn format_speed(bytes_per_second: u64) -> String {
    format!("{}/s", format_bytes(bytes_per_second))
}

pub fn format_duration(total_seconds: u64) -> String {
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_byte_scales() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.00 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MB");
    }

    #[test]
    fn formats_duration() {
        assert_eq!(format_duration(0), "00:00:00");
        assert_eq!(format_duration(3661), "01:01:01");
    }
}
