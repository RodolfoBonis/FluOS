//! Static icon/color tables generated at build time from the vendored gem YAML.
//!
//! See `build.rs`. These maps are compiled into the binary, so there is no
//! YAML parsing at startup. Runtime user overrides are layered on top by
//! [`crate::config`].

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// SGR parameter body for a Rainbow/X11 color name (e.g. `"38;5;39"`), or
/// `None` if the name is unknown. Captured from Rainbow for byte parity.
pub fn color_code(name: &str) -> Option<&'static str> {
    X11_COLORS.get(name).copied()
}
