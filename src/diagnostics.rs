#[derive(Debug, Default)]
pub struct Diagnostics {
    pub failed_operations: usize,
    pub examples: Vec<String>,
}

impl Diagnostics {
    pub fn record(&mut self, message: impl Into<String>) {
        self.failed_operations += 1;
        if self.examples.len() < 8 {
            self.examples.push(message.into());
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.failed_operations += other.failed_operations;
        let remaining = 8 - self.examples.len();
        self.examples
            .extend(other.examples.into_iter().take(remaining));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_failure_count_with_bounded_examples() {
        let mut all = Diagnostics::default();
        let mut more = Diagnostics::default();
        for _ in 0..20 {
            more.record("failed query");
        }
        all.record("first failure");
        all.merge(more);
        assert_eq!(all.failed_operations, 21);
        assert_eq!(all.examples.len(), 8);
        assert_eq!(all.examples[0], "first failure");
    }
}
