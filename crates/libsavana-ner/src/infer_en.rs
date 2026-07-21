//! English bert-base-NER ONNX backend — mirror of `_OnnxEn` in
//! `server/security/ner_gate.py` (lines 180-250).
//!
//! Owns the ONNX Runtime session, the WordPiece tokenizer, the id→label list
//! (from `config.json`) and the set of declared input names. The only numeric
//! surface is [`EnModel::logits`], which feeds a single token window through
//! the model and returns the `[n, L]` logits matrix (batch dim dropped). All
//! BIO decoding / windowing lives in `decode_en.rs`, exactly as the Python
//! splits `_run_window` (numeric) from `extract` (decode/windowing).
//!
//! ONNX Runtime parity with Python is achieved by `ort`'s `load-dynamic`
//! feature pointing `ORT_DYLIB_PATH` at the SAME `libonnxruntime` Python
//! loads — identical kernels, identical results.

use crate::wordpiece::WordPiece;
use ndarray::{Array2, Axis, Ix2};
use ort::value::Tensor;
use std::collections::HashSet;
use std::path::Path;

/// Loaded English NER backend: session + tokenizer + labels + input-name set.
pub struct EnModel {
    session: ort::session::Session,
    wp: WordPiece,
    labels: Vec<String>,
    input_names: HashSet<String>,
}

impl EnModel {
    /// Build the session on `en/model_quantized.onnx` with the CPU execution
    /// provider (mirrors Python `providers=["CPUExecutionProvider"]`), load
    /// the WordPiece vocab and the id2label list, and record which inputs the
    /// graph declares (`attention_mask` / `token_type_ids` are optional).
    pub fn load(assets: &Path) -> ort::Result<Self> {
        let session = ort::session::Session::builder()?
            .with_execution_providers([
                ort::execution_providers::CPUExecutionProvider::default().build()
            ])?
            .commit_from_file(assets.join("en/model_quantized.onnx"))?;
        let input_names = session.inputs.iter().map(|i| i.name.clone()).collect();
        let wp = WordPiece::from_vocab_file(assets.join("en/vocab.txt"))
            .map_err(|e| ort::Error::new(e.to_string()))?;
        let labels = crate::assets::read_labels(assets.join("en/config.json"))
            .map_err(|e| ort::Error::new(e.to_string()))?;
        Ok(Self {
            session,
            wp,
            labels,
            input_names,
        })
    }

    /// The id→label list from `config.json` (e.g. `O, B-MISC, …, I-LOC`).
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Access to the tokenizer (the decoder needs `encode` / `cls_id` /
    /// `sep_id` to build windows).
    pub fn wordpiece(&self) -> &WordPiece {
        &self.wp
    }

    /// Run one token window and return the `[n, L]` logits (batch dim dropped).
    ///
    /// Mirrors Python `_run_window`'s feed construction exactly: `input_ids`
    /// is always fed as int64; `attention_mask` (ones) and `token_type_ids`
    /// (zeros) are fed ONLY when the graph declares an input of that name.
    /// Output `[0]` is `[1, n, L]`; the leading batch axis is removed.
    pub fn logits(&mut self, token_ids: &[i64]) -> ort::Result<Array2<f32>> {
        let n = token_ids.len();
        let mut feed: Vec<(
            std::borrow::Cow<'static, str>,
            ort::session::SessionInputValue<'_>,
        )> = Vec::with_capacity(3);

        let input_ids = Tensor::from_array(([1usize, n], token_ids.to_vec()))?;
        feed.push(("input_ids".into(), input_ids.into()));

        if self.input_names.contains("attention_mask") {
            let attention_mask = Tensor::from_array(([1usize, n], vec![1i64; n]))?;
            feed.push(("attention_mask".into(), attention_mask.into()));
        }
        if self.input_names.contains("token_type_ids") {
            let token_type_ids = Tensor::from_array(([1usize, n], vec![0i64; n]))?;
            feed.push(("token_type_ids".into(), token_type_ids.into()));
        }

        let outputs = self.session.run(feed)?;
        // Output[0] is the logits tensor with shape [1, n, L].
        let view = outputs[0].try_extract_array::<f32>()?;
        // Drop the batch axis → [n, L], then materialise as a 2-D owned array.
        let logits = view
            .index_axis(Axis(0), 0)
            .to_owned()
            .into_dimensionality::<Ix2>()
            .map_err(|e| ort::Error::new(e.to_string()))?;
        Ok(logits)
    }
}
