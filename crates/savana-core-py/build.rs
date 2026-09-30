fn main() {
    // Extension symbols are provided by the Python interpreter. In particular,
    // macOS cdylibs need dynamic_lookup; plain cargo builds must match wheels.
    pyo3_build_config::add_extension_module_link_args();
}
