//! Frozen transformer-reference executor (plan §7), independent implementation.
//! Integer-only; uses the independent `fixed` primitives and `exp` table. Shares
//! no code with the reference (separate crate). Semantics are identical.

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
    SequenceOverflow,
}

fn rd_i16(b: &[u8], p: &mut usize) -> i16 {
    let v = i16::from_le_bytes([b[*p], b[*p + 1]]);
    *p += 2;
    v
}

impl Model {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(MODEL_LEN);
        o.extend_from_slice(&MODEL_MAGIC.to_le_bytes());
        o.extend_from_slice(&MODEL_VERSION.to_le_bytes());
        let put = |o: &mut Vec<u8>, v: i16| o.extend_from_slice(&v.to_le_bytes());
        for &g in &self.attn_gamma {
            put(&mut o, g);
        }
        for m in [&self.wq, &self.wk, &self.wv, &self.wo] {
            for row in m {
                for &v in row {
                    put(&mut o, v);
                }
            }
        }
        for &g in &self.ffn_gamma {
            put(&mut o, g);
        }
        for row in &self.w1 {
            for &v in row {
                put(&mut o, v);
            }
        }
        for row in &self.w2 {
            for &v in row {
                put(&mut o, v);
            }
        }
        for &g in &self.final_gamma {
            put(&mut o, g);
        }
        for row in &self.lmhead {
            for &v in row {
                put(&mut o, v);
            }
        }
        o
    }

    pub fn decode(b: &[u8]) -> Result<Model, ExecError> {
        if b.len() != MODEL_LEN {
            return Err(ExecError::BadLength);
        }
        if u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != MODEL_MAGIC {
            return Err(ExecError::BadMagic);
        }
        if u16::from_le_bytes([b[4], b[5]]) != MODEL_VERSION {
            return Err(ExecError::BadVersion);
        }
        let mut p = 6usize;
        let g8 = |p: &mut usize| {
            let mut a = [0i16; 8];
            for x in a.iter_mut() {
                *x = rd_i16(b, p);
            }
            a
        };
        let attn_gamma = g8(&mut p);
        let m88 = |p: &mut usize| {
            let mut m = [[0i16; 8]; 8];
            for row in m.iter_mut() {
                for x in row.iter_mut() {
                    *x = rd_i16(b, p);
                }
            }
            m
        };
        let wq = m88(&mut p);
        let wk = m88(&mut p);
        let wv = m88(&mut p);
        let wo = m88(&mut p);
        let ffn_gamma = g8(&mut p);
        let mut w1 = [[0i16; 16]; 8];
        for row in w1.iter_mut() {
            for x in row.iter_mut() {
                *x = rd_i16(b, &mut p);
            }
        }
        let mut w2 = [[0i16; 8]; 16];
        for row in w2.iter_mut() {
            for x in row.iter_mut() {
                *x = rd_i16(b, &mut p);
            }
        }
        let final_gamma = g8(&mut p);
        let mut lmhead = [[0i16; 16]; 8];
        for row in lmhead.iter_mut() {
            for x in row.iter_mut() {
                *x = rd_i16(b, &mut p);
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

    pub fn model_id(&self) -> [u8; 32] {
        crate::plain(&self.encode())
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
            let z = (max_logit as i32) - (lg as i32);
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
    let mut kv = prior_kv.to_vec();
    kv.push((k, v));
    let attn = attention(table, &q, &kv);
    let wo_out = dense(&attn, &model.wo);
    let x2 = residual_add(input_residual, &wo_out);
    let n2 = rmsnorm(&x2, &model.ffn_gamma);
    let mut h = dense(&n2, &model.w1);
    for e in h.iter_mut() {
        if *e < 0 {
            *e = 0;
        }
    }
    let f = dense(&h, &model.w2);
    let x3 = residual_add(&x2, &f);
    Ok((x3, (k, v)))
}

pub fn select_token(model: &Model, final_residual: &[i16; 8]) -> (u32, u8) {
    let n = rmsnorm(final_residual, &model.final_gamma);
    let logits = dense(&n, &model.lmhead);
    let mut best = 0usize;
    for j in 1..VOCAB {
        if logits[j] > logits[best] {
            best = j;
        }
    }
    let sel = best as u32;
    (sel, if sel == EOS { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> [[i16; 8]; 8] {
        let mut m = [[0i16; 8]; 8];
        for (i, row) in m.iter_mut().enumerate() {
            row[i] = 256;
        }
        m
    }
    fn tiny() -> Model {
        Model {
            attn_gamma: [256; 8],
            wq: ident(),
            wk: ident(),
            wv: ident(),
            wo: ident(),
            ffn_gamma: [256; 8],
            w1: [[16; 16]; 8],
            w2: [[16; 8]; 16],
            final_gamma: [256; 8],
            lmhead: {
                let mut m = [[0i16; 16]; 8];
                for row in m.iter_mut() {
                    row[3] = 300;
                }
                m
            },
        }
    }

    #[test]
    fn roundtrip_and_exec() {
        let m = tiny();
        assert_eq!(m.encode().len(), MODEL_LEN);
        assert_eq!(Model::decode(&m.encode()).unwrap(), m);
        let t = exp::table_cached();
        let (o0, kv0) = layer_group(t, &m, &[100, -50, 25, 10, -5, 0, 200, -128], &[]).unwrap();
        let _ = layer_group(t, &m, &o0, &[kv0]).unwrap();
        assert_eq!(select_token(&m, &[100; 8]).0, 3);
    }

    #[test]
    fn overflow_and_bad_header() {
        let m = tiny();
        let prior = vec![([0i16; 8], [0i16; 8]); MAX_SEQ];
        assert_eq!(
            layer_group(exp::table_cached(), &m, &[0; 8], &prior),
            Err(ExecError::SequenceOverflow)
        );
        let mut b = m.encode();
        b[0] ^= 1;
        assert_eq!(Model::decode(&b), Err(ExecError::BadMagic));
    }
}
