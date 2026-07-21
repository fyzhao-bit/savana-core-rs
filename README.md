# savana-core-rs

Savana's shared security kernel, ported to Rust. Slice 1 of this workspace is
`libsavana-ner`, a Rust port of the Python NER (named-entity recognition)
security module used to detect and mask sensitive spans in text before they
leave the device. The whole workspace builds with `#![forbid(unsafe_code)]`
enforced at the lint level. ONNX model assets are not vendored in this
repository; they are resolved at runtime via the `SAVANA_NER_ASSETS`
environment variable, which should point at a local directory containing the
model files.
