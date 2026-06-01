use std::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(2); // INFO

pub fn set_level(name: &str) {
    let l = match name.to_ascii_uppercase().as_str() {
        "DEBUG" => 1, "INFO" => 2, "WARN" => 3, "ERROR" => 4, _ => 2,
    };
    LEVEL.store(l, Ordering::Relaxed);
}

pub fn enabled(l: u8) -> bool { l >= LEVEL.load(Ordering::Relaxed) }

#[macro_export]
macro_rules! logln {
    ($lvl:expr, $tag:expr, $($arg:tt)*) => {{
        if $crate::log::enabled($lvl) {
            eprintln!("[{}] {}", $tag, format_args!($($arg)*));
        }
    }};
}
#[macro_export] macro_rules! debug { ($($a:tt)*) => { $crate::logln!(1, "DEBUG", $($a)*) } }
#[macro_export] macro_rules! info  { ($($a:tt)*) => { $crate::logln!(2, "INFO",  $($a)*) } }
#[macro_export] macro_rules! warn  { ($($a:tt)*) => { $crate::logln!(3, "WARN",  $($a)*) } }
#[macro_export] macro_rules! error { ($($a:tt)*) => { $crate::logln!(4, "ERROR", $($a)*) } }
