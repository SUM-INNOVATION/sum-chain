//! Frozen transformer-reference executor (plan §7). Integer-only.
//!
//! Byte-identical logic to the frozen reference
//! `b0-pre-validator/src/transformer.rs` (the guest cannot depend on that
//! std+bignum host tool). `tests/reference_agreement.rs` re-runs the official
//! golden workload through this executor and rejects any divergence.
//!
//! Dims: `d_model=8, n_heads=2, head_dim=4, ffn_dim=16, vocab=16, MAX_SEQ=8`.
//! One bias-free layer: RMSNorm1(attn_γ) → Q/K/V → 2-head masked softmax
//! attention (score ÷512, weights from the committed exp table) → Wo →
//! residual-add → RMSNorm2(ffn_γ) → dense(→16) → ReLU → dense(→8) →
//! residual-add. SelectToken: RMSNorm(final_γ) → LM head → strict-`>` argmax
//! (tie → lowest) → `eos = (selected == 15)`.

use crate::exp;
use crate::fixed::{isqrt, requantize, rhaz, saturate};

pub const D_MODEL: usize = 8;
pub const N_HEADS: usize = 2;
pub const HEAD_DIM: usize = 4;
pub const FFN_DIM: usize = 16;
pub const VOCAB: usize = 16;
pub const MAX_SEQ: usize = 8;
pub const EOS: u32 = 15;

pub const MODEL_MAGIC: u32 = 0x5230_4D44;
pub const MODEL_VERSION: u16 = 1;
pub const MODEL_LEN: usize = 1334;

/// A per-position (K, V) pair.
pub type Kv = ([i16; 8], [i16; 8]);
/// Layer-group output: `(output_residual, current_kv)`.
pub type LayerOutput = ([i16; 8], Kv);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub attn_gamma: [i16; 8],
    pub wq: [[i16; 8]; 8],
    pub wk: [[i16; 8]; 8],
    pub wv: [[i16; 8]; 8],
    pub wo: [[i16; 8]; 8],
    pub ffn_gamma: [i16; 8],
    pub w1: [[i16; 16]; 8],
    pub w2: [[i16; 8]; 16],
    pub final_gamma: [i16; 8],
    pub lmhead: [[i16; 16]; 8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExecError {
    BadMagic,
    BadVersion,
    BadLength,
    KvShape,
    SequenceOverflow,
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}
impl Cur<'_> {
    fn i16(&mut self) -> i16 {
        let v = i16::from_le_bytes([self.b[self.p], self.b[self.p + 1]]);
        self.p += 2;
        v
    }
}

fn wr_i16(out: &mut Vec<u8>, v: i16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn read_g8(c: &mut Cur) -> [i16; 8] {
    let mut a = [0i16; 8];
    for x in a.iter_mut() {
        *x = c.i16();
    }
    a
}
fn read_m88(c: &mut Cur) -> [[i16; 8]; 8] {
    let mut m = [[0i16; 8]; 8];
    for row in m.iter_mut() {
        for x in row.iter_mut() {
            *x = c.i16();
        }
    }
    m
}

impl Model {
    /// Encode to the canonical 1334-byte model.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(MODEL_LEN);
        o.extend_from_slice(&MODEL_MAGIC.to_le_bytes());
        o.extend_from_slice(&MODEL_VERSION.to_le_bytes());
        for &g in &self.attn_gamma {
            wr_i16(&mut o, g);
        }
        for m in [&self.wq, &self.wk, &self.wv, &self.wo] {
            for row in m {
                for &v in row {
                    wr_i16(&mut o, v);
                }
            }
        }
        for &g in &self.ffn_gamma {
            wr_i16(&mut o, g);
        }
        for row in &self.w1 {
            for &v in row {
                wr_i16(&mut o, v);
            }
        }
        for row in &self.w2 {
            for &v in row {
                wr_i16(&mut o, v);
            }
        }
        for &g in &self.final_gamma {
            wr_i16(&mut o, g);
        }
        for row in &self.lmhead {
            for &v in row {
                wr_i16(&mut o, v);
            }
        }
        o
    }

    pub fn decode(bytes: &[u8]) -> Result<Model, ExecError> {
        if bytes.len() != MODEL_LEN {
            return Err(ExecError::BadLength);
        }
        if u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != MODEL_MAGIC {
            return Err(ExecError::BadMagic);
        }
        if u16::from_le_bytes([bytes[4], bytes[5]]) != MODEL_VERSION {
            return Err(ExecError::BadVersion);
        }
        let mut c = Cur { b: bytes, p: 6 };
        let attn_gamma = read_g8(&mut c);
        let wq = read_m88(&mut c);
        let wk = read_m88(&mut c);
        let wv = read_m88(&mut c);
        let wo = read_m88(&mut c);
        let ffn_gamma = read_g8(&mut c);
        let mut w1 = [[0i16; 16]; 8];
        for row in w1.iter_mut() {
            for x in row.iter_mut() {
                *x = c.i16();
            }
        }
        let mut w2 = [[0i16; 8]; 16];
        for row in w2.iter_mut() {
            for x in row.iter_mut() {
                *x = c.i16();
            }
        }
        let final_gamma = read_g8(&mut c);
        let mut lmhead = [[0i16; 16]; 8];
        for row in lmhead.iter_mut() {
            for x in row.iter_mut() {
                *x = c.i16();
            }
        }
        Ok(Model {
            attn_gamma,
            wq,
            wk,
            wv,
            wo,
            ffn_gamma,
            w1,
            w2,
            final_gamma,
            lmhead,
        })
    }

    /// `model_id = BLAKE3(canonical_model_bytes)`.
    pub fn model_id(&self) -> [u8; 32] {
        blake3::hash(&self.encode()).into()
    }
}

fn rmsnorm<const N: usize>(x: &[i16; N], gamma: &[i16; N]) -> [i16; N] {
    let mut ss: i64 = 0;
    for &v in x {
        ss += v as i64 * v as i64;
    }
    let rms = isqrt(ss / N as i64 + 1);
    let mut out = [0i16; N];
    for i in 0..N {
        out[i] = saturate(rhaz(x[i] as i64 * gamma[i] as i64, rms));
    }
    out
}

fn dense<const N: usize, const M: usize>(input: &[i16; N], w: &[[i16; M]; N]) -> [i16; M] {
    let mut out = [0i16; M];
    for (j, o) in out.iter_mut().enumerate() {
        let mut acc: i64 = 0;
        for i in 0..N {
            acc += input[i] as i64 * w[i][j] as i64;
        }
        *o = saturate(requantize(acc));
    }
    out
}

fn residual_add<const N: usize>(a: &[i16; N], b: &[i16; N]) -> [i16; N] {
    let mut out = [0i16; N];
    for i in 0..N {
        out[i] = saturate(a[i] as i64 + b[i] as i64);
    }
    out
}

/// One-step 2-head masked-softmax attention. `kv` is the full sequence
/// (prior + current), all positions `<= position` (implicit causal mask).
fn attention(table: &[u32], q: &[i16; 8], kv: &[Kv]) -> [i16; 8] {
    let mut attn = [0i16; 8];
    for h in 0..N_HEADS {
        let lo = h * HEAD_DIM;
        let hi = lo + HEAD_DIM;
        let mut logits = Vec::with_capacity(kv.len());
        for (k, _) in kv {
            let mut acc: i64 = 0;
            for d in lo..hi {
                acc += q[d] as i64 * k[d] as i64;
            }
            logits.push(saturate(rhaz(acc, 512)));
        }
        let max_logit = *logits.iter().max().unwrap();
        let mut weights = Vec::with_capacity(kv.len());
        let mut den: i64 = 0;
        for &lg in &logits {
            let z = (max_logit as i32) - (lg as i32); // >= 0
            let w = exp::lookup(table, z as u32);
            weights.push(w);
            den += w as i64;
        }
        for d in lo..hi {
            let mut acc: i64 = 0;
            for (j, (_, v)) in kv.iter().enumerate() {
                acc += weights[j] as i64 * v[d] as i64;
            }
            attn[d] = saturate(rhaz(acc, den));
        }
    }
    attn
}

/// Execute a TransformerLayerGroup at `position = prior_kv.len()`.
/// Returns `(output_residual, current_kv)`; the output KV cache is
/// `prior_kv` followed by `current_kv`.
pub fn layer_group(
    table: &[u32],
    model: &Model,
    input_residual: &[i16; 8],
    prior_kv: &[Kv],
) -> Result<LayerOutput, ExecError> {
    if prior_kv.len() >= MAX_SEQ {
        return Err(ExecError::SequenceOverflow);
    }
    let n1 = rmsnorm(input_residual, &model.attn_gamma);
    let q = dense(&n1, &model.wq);
    let k = dense(&n1, &model.wk);
    let v = dense(&n1, &model.wv);

    let mut kv: Vec<([i16; 8], [i16; 8])> = prior_kv.to_vec();
    kv.push((k, v));

    let attn = attention(table, &q, &kv);
    let wo_out = dense(&attn, &model.wo);
    let x2 = residual_add(input_residual, &wo_out);

    let n2 = rmsnorm(&x2, &model.ffn_gamma);
    let mut h = dense(&n2, &model.w1); // -> 16
    for e in h.iter_mut() {
        if *e < 0 {
            *e = 0;
        }
    }
    let f = dense(&h, &model.w2); // -> 8
    let x3 = residual_add(&x2, &f);
    Ok((x3, (k, v)))
}

/// SelectToken over a final residual: returns `(selected_token, eos_flag)`.
pub fn select_token(model: &Model, final_residual: &[i16; 8]) -> (u32, u8) {
    let n = rmsnorm(final_residual, &model.final_gamma);
    let logits = dense(&n, &model.lmhead); // -> 16
    let mut best = 0usize;
    for j in 1..VOCAB {
        if logits[j] > logits[best] {
            best = j; // strict > ; ties keep the lower index
        }
    }
    let sel = best as u32;
    (sel, if sel == EOS { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_model() -> Model {
        let g = [256i16; 8]; // gamma = 1.0 in Q8
        let ident = {
            let mut m = [[0i16; 8]; 8];
            for (i, row) in m.iter_mut().enumerate() {
                row[i] = 256;
            }
            m
        };
        Model {
            attn_gamma: g,
            wq: ident,
            wk: ident,
            wv: ident,
            wo: ident,
            ffn_gamma: g,
            w1: [[16i16; 16]; 8],
            w2: [[16i16; 8]; 16],
            final_gamma: g,
            lmhead: {
                let mut m = [[0i16; 16]; 8];
                for row in m.iter_mut() {
                    row[3] = 300;
                    row[7] = 100;
                }
                m
            },
        }
    }

    #[test]
    fn model_roundtrip_and_length() {
        let m = tiny_model();
        let bytes = m.encode();
        assert_eq!(bytes.len(), MODEL_LEN);
        assert_eq!(Model::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn bad_magic_version_length_rejected() {
        let m = tiny_model();
        let mut b = m.encode();
        b[0] ^= 1;
        assert_eq!(Model::decode(&b), Err(ExecError::BadMagic));
        let mut b = m.encode();
        b[4] = 2;
        assert_eq!(Model::decode(&b), Err(ExecError::BadVersion));
        assert_eq!(
            Model::decode(&m.encode()[..1333]),
            Err(ExecError::BadLength)
        );
    }

    #[test]
    fn select_token_argmax_tie_lowest_and_eos() {
        let m = tiny_model();
        let (sel, eos) = select_token(&m, &[100; 8]);
        assert_eq!(sel, 3);
        assert_eq!(eos, 0);
        let mut m2 = m.clone();
        for i in 0..8 {
            m2.lmhead[i] = [0; 16];
            m2.lmhead[i][15] = 300;
        }
        let (sel2, eos2) = select_token(&m2, &[100; 8]);
        assert_eq!(sel2, 15);
        assert_eq!(eos2, 1);
        let mut m3 = m.clone();
        for i in 0..8 {
            m3.lmhead[i] = [0; 16];
        }
        assert_eq!(select_token(&m3, &[100; 8]).0, 0);
    }

    #[test]
    fn sequence_overflow_rejected() {
        let t = exp::table();
        let m = tiny_model();
        let prior = vec![([0i16; 8], [0i16; 8]); MAX_SEQ];
        assert_eq!(
            layer_group(t, &m, &[0; 8], &prior),
            Err(ExecError::SequenceOverflow)
        );
    }
}
