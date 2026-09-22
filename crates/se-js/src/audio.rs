//! Minimal deterministic audio DSP for the M4 audio fingerprint tier
//! (firing 27). The engine has no audio output device, but OfflineAudioContext
//! rendering must not be a constant: fingerprint scripts sum
//! `getChannelData()` output and compare configs (frequencies, waveform
//! types, compressor on/off) to catch stubbed audio. This module renders
//! the subset of the Web Audio graph those scripts build — oscillators
//! through optional gain and a soft-knee dynamics compressor — with real
//! waveform math, so different graphs produce different buffers and the
//! same graph produces the same buffer every time (cross-run determinism
//! is what a stable fingerprint needs; it matches the canvas tier's
//! fixed-deterministic choice).

/// Desktop Chrome's default sample rate.
pub const SAMPLE_RATE: f64 = 44100.0;

/// Oscillator waveform kinds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OscKind {
    Sine,
    Triangle,
    Square,
    Sawtooth,
}

impl OscKind {
    pub fn from(s: &str) -> Self {
        match s {
            "triangle" => Self::Triangle,
            "square" => Self::Square,
            "sawtooth" => Self::Sawtooth,
            // 'sine' and 'custom' (no PeriodicWave rendering this tier)
            _ => Self::Sine,
        }
    }
}

/// One oscillator period sample; `phase` is cycles [0, 1).
pub fn osc_sample(kind: OscKind, phase: f64) -> f32 {
    let p = phase - phase.floor();
    match kind {
        OscKind::Sine => (2.0 * std::f64::consts::PI * p).sin() as f32,
        OscKind::Triangle => (1.0 - 4.0 * (p - 0.5).abs()) as f32,
        OscKind::Square => {
            if p < 0.5 {
                1.0
            } else {
                -1.0
            }
        }
        OscKind::Sawtooth => (2.0 * p - 1.0) as f32,
    }
}

/// Soft-knee dynamics compressor following the Web Audio gain-computer
/// curve with an attack/release envelope follower (default-ish params).
pub struct Compressor {
    pub threshold_db: f64,
    pub knee_db: f64,
    pub ratio: f64,
    pub attack_s: f64,
    pub release_s: f64,
    env: f64,
}

impl Compressor {
    pub fn defaults() -> Self {
        Self {
            threshold_db: -24.0,
            knee_db: 30.0,
            ratio: 12.0,
            attack_s: 0.003,
            release_s: 0.25,
            env: 0.0,
        }
    }

    /// Full-parameter constructor for the bridge render walk (the JS graph's
    /// compressor params are read off the live AudioParam objects).
    pub fn with_params(
        threshold_db: f64,
        knee_db: f64,
        ratio: f64,
        attack_s: f64,
        release_s: f64,
    ) -> Self {
        Self {
            threshold_db,
            knee_db,
            ratio: ratio.max(1.0),
            attack_s: attack_s.max(1e-4),
            release_s: release_s.max(1e-4),
            env: 0.0,
        }
    }

    pub fn process_sample(&mut self, x: f32) -> f32 {
        let x = x as f64;
        let ax = x.abs();
        // Envelope follower; attack coefficient per-sample.
        let coeff = if ax > self.env { self.attack_s } else { self.release_s };
        let k = (-1.0 / (coeff.max(1e-4) * SAMPLE_RATE)).exp();
        self.env = ax + (self.env - ax) * k;
        let x_db = self.env.max(1e-8).log10() * 20.0;
        let over = x_db - self.threshold_db;
        let out_db = if 2.0 * over < -self.knee_db {
            x_db
        } else if 2.0 * over > self.knee_db {
            self.threshold_db + over / self.ratio
        } else {
            // Soft knee: quadratic blend region.
            let half_k = self.knee_db / 2.0;
            x_db + (1.0 / self.ratio - 1.0) * (over + half_k).powi(2) / (2.0 * self.knee_db)
        };
        let gain = 10f64.powf((out_db - x_db) / 20.0);
        (x * gain) as f32
    }
}

/// One renderable chain: a source through optional gain and compressor.
pub struct RenderChain {
    pub osc: Option<(OscKind, f64)>,
    pub buffer: Option<Vec<f32>>,
    pub gain: f64,
    pub compress: Option<Compressor>,
}

impl RenderChain {
    pub fn silence() -> Self {
        Self {
            osc: None,
            buffer: None,
            gain: 1.0,
            compress: None,
        }
    }
}

/// Render `len` samples of the chain (mono).
pub fn render_chain(chain: &mut RenderChain, len: usize) -> Vec<f32> {
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let mut s = if let Some((kind, freq)) = chain.osc {
            osc_sample(kind, freq * i as f64 / SAMPLE_RATE)
        } else if let Some(buf) = &chain.buffer {
            buf.get(i).copied().unwrap_or(0.0)
        } else {
            0.0
        };
        s = (s as f64 * chain.gain) as f32;
        if let Some(comp) = &mut chain.compress {
            s = comp.process_sample(s);
        }
        out.push(s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Energy (sum of squares) — robust to signed cancellation when a render
    /// spans an integer number of periods.
    fn energy(v: &[f32]) -> f64 {
        v.iter().map(|x| (*x as f64) * (*x as f64)).sum()
    }

    #[test]
    fn sine_render_is_deterministic_and_nonzero() {
        let mut a = RenderChain {
            osc: Some((OscKind::Sine, 1000.0)),
            buffer: None,
            gain: 1.0,
            compress: None,
        };
        let mut b = RenderChain {
            osc: Some((OscKind::Sine, 1000.0)),
            buffer: None,
            gain: 1.0,
            compress: None,
        };
        let ra = render_chain(&mut a, 44100);
        let rb = render_chain(&mut b, 44100);
        assert_eq!(ra, rb);
        assert!(energy(&ra) > 1000.0, "energy {}", energy(&ra));
    }

    #[test]
    fn different_frequencies_and_waveforms_differ() {
        let mut s1 = RenderChain {
            osc: Some((OscKind::Sine, 1000.0)),
            ..RenderChain::silence()
        };
        let mut s2 = RenderChain {
            osc: Some((OscKind::Sine, 2000.0)),
            ..RenderChain::silence()
        };
        let mut tri = RenderChain {
            osc: Some((OscKind::Triangle, 1000.0)),
            ..RenderChain::silence()
        };
        let r1 = render_chain(&mut s1, 4410);
        let r2 = render_chain(&mut s2, 4410);
        let rt = render_chain(&mut tri, 4410);
        // Vectors must differ (summaries like energy can collide: any full-
        // amplitude sine over integer cycles has energy N/2).
        assert_ne!(r1, r2);
        assert_ne!(r1, rt);
    }

    #[test]
    fn compressor_limits_peaks() {
        let mut raw = RenderChain {
            osc: Some((OscKind::Square, 440.0)),
            ..RenderChain::silence()
        };
        let mut comp = RenderChain {
            osc: Some((OscKind::Square, 440.0)),
            ..RenderChain::silence()
        };
        comp.compress = Some(Compressor::defaults());
        let r_raw = render_chain(&mut raw, 44100);
        let r_comp = render_chain(&mut comp, 44100);
        // The envelope starts at 0 so the very first transient passes (same
        // as a real Web Audio compressor); measure the steady-state tail.
        let tail = |v: &[f32]| {
            v[10000..]
                .iter()
                .map(|x| x.abs())
                .fold(0.0f32, f32::max)
        };
        let peak_raw = tail(&r_raw);
        let peak_comp = tail(&r_comp);
        assert!(
            peak_comp < peak_raw * 0.5,
            "raw={peak_raw} comp={peak_comp}"
        );
        // Overall energy must drop too (not just the tail).
        let energy = |v: &[f32]| v.iter().map(|x| (*x as f64).powi(2)).sum::<f64>();
        assert!(energy(&r_comp) < energy(&r_raw) * 0.5);
    }

    #[test]
    fn gain_scales_and_silence_is_zero() {
        let mut g = RenderChain {
            osc: Some((OscKind::Sine, 500.0)),
            gain: 0.5,
            ..RenderChain::silence()
        };
        let mut full = RenderChain {
            osc: Some((OscKind::Sine, 500.0)),
            ..RenderChain::silence()
        };
        let mut silent = RenderChain::silence();
        let rg = render_chain(&mut g, 4410);
        let rf = render_chain(&mut full, 4410);
        let rs = render_chain(&mut silent, 4410);
        assert!((energy(&rg) - energy(&rf) * 0.25).abs() < 1.0);
        assert_eq!(energy(&rs), 0.0);
    }
}
