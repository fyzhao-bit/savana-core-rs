//! Chinese Baidu LAC (char-level + CRF) ONNX backend — mirror of `_OnnxZh`
//! in `server/security/ner_gate.py` (lines 283-347).
//!
//! Owns the ONNX Runtime session plus the four LAC assets: the word vocab
//! (`zh/word.dic`, value-first, with an `"OOV"` fallback id), the id→tag map
//! (`zh/tag.dic`, id-first), the fullwidth→halfwidth normaliser (`zh/q2b.dic`)
//! and the CRF transition matrix (`zh/crf.bin`, `NTAGS x NTAGS` little-endian
//! f32). The only numeric surface is [`ZhModel::emissions`], which feeds the
//! char-id sequence through the encoder and returns the `[n, NTAGS]` emission
//! matrix (batch dim dropped). The Viterbi decode / BIO grouping lives in
//! `decode_zh.rs`, exactly as Python splits `extract` from the raw session run.
//!
//! ONNX Runtime parity with Python comes from `ort`'s `load-dynamic` feature
//! pointing `ORT_DYLIB_PATH` at the SAME `libonnxruntime` Python loads.

use crate::Span;
use ndarray::{Array2, Axis, Ix2};
use ort::value::Tensor;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Number of CRF/emission tags the encoder emits. The `zh/tag.dic` file maps
/// only 49 of these; ids in `49..59` are unmapped and the decoder defaults
/// them to the literal `"n-B"` (see `decode_zh`).
pub const NTAGS: usize = 59;

/// Loaded Chinese LAC backend: session + vocab + tag map + q2b + CRF matrix
/// + declared input-name set.
pub struct ZhModel {
    session: ort::session::Session,
    vocab: HashMap<String, i64>,
    oov: i64,
    id2tag: HashMap<i64, String>,
    q2b: HashMap<String, String>,
    trans: Array2<f32>,
    input_names: HashSet<String>,
}

impl ZhModel {
    /// Build the session on `zh/lac_encoder.onnx` with the CPU execution
    /// provider (mirrors Python `providers=["CPUExecutionProvider"]`), load
    /// the vocab (`oov` = `vocab["OOV"]` or 0), the id→tag map, the q2b table
    /// and the CRF transition matrix, and record the declared input names
    /// (`length` is optional).
    pub fn load(assets: &Path) -> ort::Result<Self> {
        let session = ort::session::Session::builder()?
            .with_execution_providers([
                ort::execution_providers::CPUExecutionProvider::default().build()
            ])?
            .commit_from_file(assets.join("zh/lac_encoder.onnx"))?;
        let input_names = session.inputs.iter().map(|i| i.name.clone()).collect();
        let vocab = crate::assets::read_dic_value_first(assets.join("zh/word.dic"))
            .map_err(|e| ort::Error::new(e.to_string()))?;
        let oov = vocab.get("OOV").copied().unwrap_or(0);
        let id2tag = crate::assets::read_dic_id_first(assets.join("zh/tag.dic"))
            .map_err(|e| ort::Error::new(e.to_string()))?;
        let q2b = crate::assets::read_kv(assets.join("zh/q2b.dic"))
            .map_err(|e| ort::Error::new(e.to_string()))?;
        let trans = crate::assets::read_crf(assets.join("zh/crf.bin"), NTAGS)
            .map_err(|e| ort::Error::new(e.to_string()))?;
        Ok(Self {
            session,
            vocab,
            oov,
            id2tag,
            q2b,
            trans,
            input_names,
        })
    }

    /// The CRF transition matrix (`[NTAGS, NTAGS]`, `trans[from, to]`), needed
    /// by the Viterbi decode.
    pub fn trans(&self) -> &Array2<f32> {
        &self.trans
    }

    /// The id→tag map (`zh/tag.dic`). Unmapped ids (`49..59`) default to
    /// `"n-B"` in the decoder, not here.
    pub fn id2tag(&self) -> &HashMap<i64, String> {
        &self.id2tag
    }

    /// Run the encoder over `chars` and return the `[n, NTAGS]` emission
    /// matrix (batch dim dropped).
    ///
    /// Mirrors Python exactly: each char is normalised through `q2b`
    /// (`q2b.get(c, c)`) then mapped to its vocab id (`vocab.get(., oov)`);
    /// the ids are fed as int64 `token_ids` of shape `[1, n]`; `length`
    /// (int64 `[1]` = `[n]`) is fed ONLY when the graph declares it. Output
    /// `[0]` is `[1, n, NTAGS]`; the leading batch axis is removed.
    pub fn emissions(&mut self, chars: &[char]) -> ort::Result<Array2<f32>> {
        let n = chars.len();
        let ids: Vec<i64> = chars
            .iter()
            .map(|c| {
                let key = c.to_string();
                let normalised = self.q2b.get(&key).unwrap_or(&key);
                self.vocab.get(normalised).copied().unwrap_or(self.oov)
            })
            .collect();

        let mut feed: Vec<(
            std::borrow::Cow<'static, str>,
            ort::session::SessionInputValue<'_>,
        )> = Vec::with_capacity(2);

        let token_ids = Tensor::from_array(([1usize, n], ids))?;
        feed.push(("token_ids".into(), token_ids.into()));

        if self.input_names.contains("length") {
            let length = Tensor::from_array(([1usize], vec![n as i64]))?;
            feed.push(("length".into(), length.into()));
        }

        let outputs = self.session.run(feed)?;
        // Output[0] is the emission tensor with shape [1, n, NTAGS].
        let view = outputs[0].try_extract_array::<f32>()?;
        // Drop the batch axis → [n, NTAGS], then materialise as an owned 2-D array.
        let em = view
            .index_axis(Axis(0), 0)
            .to_owned()
            .into_dimensionality::<Ix2>()
            .map_err(|e| ort::Error::new(e.to_string()))?;
        Ok(em)
    }
}

/// Convenience wrapper mirroring `_OnnxZh.extract`: delegates to
/// [`crate::decode_zh::extract`] so callers can go straight from a model to
/// spans. Kept thin — all decode logic lives in `decode_zh`.
pub fn extract(model: &mut ZhModel, text: &str) -> ort::Result<Vec<Span>> {
    crate::decode_zh::extract(model, text)
}
