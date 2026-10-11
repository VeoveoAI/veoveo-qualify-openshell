use serde::Serialize;

#[derive(Serialize, Default)]
pub struct Summary {
    pub count: usize,
    pub min: u64,
    pub p50: u64,
    pub p99: u64,
    pub max: u64,
}

pub fn summarize(mut values: Vec<u64>) -> Summary {
    if values.is_empty() {
        return Summary::default();
    }
    values.sort_unstable();
    let at = |q: f64| values[((values.len() - 1) as f64 * q).round() as usize];
    Summary {
        count: values.len(),
        min: values[0],
        p50: at(0.50),
        p99: at(0.99),
        max: values[values.len() - 1],
    }
}

/// Largest gap between consecutive arrival times, which exposes buffering bursts.
pub fn max_gap(arrivals: &[u64]) -> u64 {
    arrivals.windows(2).map(|w| w[1] - w[0]).max().unwrap_or(0)
}
