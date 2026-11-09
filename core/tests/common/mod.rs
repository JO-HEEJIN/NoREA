//! Shared test fixtures: the test-only PRNG and the WP-02 synthetic dataset A
//! generator, used by distinguishability.rs and check_disclose.rs (moved here
//! from distinguishability.rs in WP-04 2차, unchanged).
#![allow(dead_code)]

use std::collections::HashSet;

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const SI_DONG: [(&str, [&str; 4]); 3] = [
    ("하남시", ["미사동", "망월동", "풍산동", "덕풍동"]),
    ("성남시", ["정자동", "서현동", "수내동", "분당동"]),
    ("용인시", ["죽전동", "보정동", "상현동", "풍덕천동"]),
];

const NOTE_WORDS: [&str; 24] = [
    "도로 접함", "맹지", "경사 있음", "주차 가능", "하천 인접", "공원 인접", "분할 예정", "합병 이력",
    "지목 변경", "현황 도로", "건축 불가", "구거 포함", "임대 중", "공유 지분", "측량 필요", "경계 분쟁",
    "개발제한", "농지 전용", "상수도 있음", "전기 인입", "학교 인근", "역세권", "고압선 통과", "문화재 인근",
];

/// Synthetic parcel data (WP-02 acceptance 3). `skewed_area`: log-uniform
/// area instead of uniform (diagnostic variant A').
pub fn dataset_a(rows: usize, skewed_area: bool, seed: u64) -> String {
    let mut r = Rng(seed);
    // id: {letter}-{3 digits}, 26 000 possible, rows distinct ones.
    let mut ids: Vec<u32> = (0..26_000).collect();
    for k in (1..ids.len()).rev() {
        let j = r.below(k + 1);
        ids.swap(k, j);
    }
    let use_types = [("대", 40), ("전", 25), ("답", 20), ("임야", 10), ("잡종지", 5)];
    let mut seen_addr = HashSet::new();
    let mut out = String::from("[\n");
    for (i, &id) in ids.iter().take(rows).enumerate() {
        let id = format!("{}-{:03}", char::from(b'A' + (id / 1000) as u8), id % 1000);
        let addr = loop {
            let (si, dongs) = SI_DONG[r.below(3)];
            let dong = dongs[r.below(4)];
            let bon = 1 + r.below(999);
            let mut bu = 1;
            while bu < 40 && r.f64() < 0.85 {
                bu += 1;
            }
            let a = format!("{si} {dong} {bon}-{bu}");
            if seen_addr.insert(a.clone()) {
                break a;
            }
        };
        let area_c: u64 = if skewed_area {
            let x = (50f64.ln() + r.f64() * (2000f64.ln() - 50f64.ln())).exp();
            (x * 100.0).round() as u64
        } else {
            5_000 + r.next() % 195_001
        };
        let mut u = r.below(100);
        let mut use_type = "";
        for (t, p) in use_types {
            if u < p {
                use_type = t;
                break;
            }
            u -= p;
        }
        let note = if r.f64() < 0.2 {
            String::new()
        } else {
            let k = 1 + r.below(3);
            let mut parts: Vec<String> = (0..k).map(|_| NOTE_WORDS[r.below(NOTE_WORDS.len())].to_string()).collect();
            if r.f64() < 0.3 {
                parts.push(format!("{}년 측량", 1990 + r.below(35)));
            }
            format!(",\n    \"note\": \"{}\"", parts.join(", "))
        };
        if i > 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            "  {{\n    \"id\": \"{id}\",\n    \"addr\": \"{addr}\",\n    \"area_m2\": {}.{:02},\n    \"use_type\": \"{use_type}\"{note}\n  }}",
            area_c / 100,
            area_c % 100
        ));
    }
    out.push_str("\n]\n");
    out
}

