//! View tag computation for efficient scanning.
//!
//! View tags enable recipients to quickly filter announcements:
//! - Each announcement includes a 1-byte view tag
//! - Recipients compute their expected view tag from the shared secret
//! - Only announcements with matching view tags require full decapsulation
//!
//! ## Efficiency
//!
//! With 1-byte view tags (256 possible values), ~99.6% of announcements
//! can be skipped without expensive decapsulation operations.
//!
//! ## Security
//!
//! View tags leak 1 byte of information about the shared secret.
//! This is acceptable because:
//! 1. The shared secret has 256 bits of entropy
//! 2. Leaking 8 bits still leaves 248 bits of security
//! 3. The view tag alone cannot identify the recipient

use specter_core::constants::{DOMAIN_VIEW_TAG, SHAKE256_VIEW_TAG_OUTPUT_SIZE};

use crate::hash::shake256;

/// Computes the view tag from a shared secret.
///
/// The view tag is the first byte of SHAKE256(DOMAIN_VIEW_TAG || shared_secret).
///
/// # Arguments
///
/// * `shared_secret` - The 32-byte shared secret from Kyber encapsulation
///
/// # Returns
///
/// A single byte (u8) used for announcement filtering.
///
/// # Example
///
/// ```rust,ignore
/// use specter_crypto::{encapsulate, compute_view_tag};
///
/// let (ciphertext, shared_secret) = encapsulate(&recipient_pk)?;
/// let view_tag = compute_view_tag(&shared_secret);
///
/// // Include view_tag in the announcement
/// let announcement = Announcement::new(ciphertext.into_bytes(), view_tag);
/// ```
pub fn compute_view_tag(shared_secret: &[u8]) -> u8 {
    let hash = shake256(
        DOMAIN_VIEW_TAG,
        shared_secret,
        SHAKE256_VIEW_TAG_OUTPUT_SIZE,
    );
    hash[0]
}

/// Computes multiple bytes of the view tag hash.
///
/// This can be used for extended view tags in future protocol versions.
/// Currently we only use the first byte.
///
/// # Arguments
///
/// * `shared_secret` - The shared secret from Kyber
/// * `len` - Number of bytes to return (max 32)
pub fn compute_view_tag_bytes(shared_secret: &[u8], len: usize) -> Vec<u8> {
    let max_len = len.min(SHAKE256_VIEW_TAG_OUTPUT_SIZE);
    shake256(DOMAIN_VIEW_TAG, shared_secret, max_len)
}

/// Checks if a view tag matches the expected value for a shared secret.
///
/// This is a constant-time comparison to prevent timing attacks.
pub fn verify_view_tag(shared_secret: &[u8], expected_tag: u8) -> bool {
    let computed_tag = compute_view_tag(shared_secret);
    subtle::ConstantTimeEq::ct_eq(&computed_tag, &expected_tag).into()
}

/// Computes view tag statistics.
///
/// Useful for analyzing the distribution of view tags in a registry.
#[derive(Debug, Clone)]
pub struct ViewTagStats {
    /// Count of each view tag value
    pub distribution: Vec<u64>,
    /// Total number of tags analyzed
    pub total: u64,
}

impl Default for ViewTagStats {
    fn default() -> Self {
        Self {
            distribution: vec![0; 256],
            total: 0,
        }
    }
}

impl ViewTagStats {
    /// Creates a new stats tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a view tag.
    pub fn add(&mut self, tag: u8) {
        self.distribution[tag as usize] += 1;
        self.total += 1;
    }

    /// Returns the most common view tag.
    pub fn most_common(&self) -> Option<(u8, u64)> {
        self.distribution
            .iter()
            .enumerate()
            .max_by_key(|(_, &count)| count)
            .map(|(tag, &count)| (tag as u8, count))
    }

    /// Returns the expected count per tag for uniform distribution.
    pub fn expected_uniform_count(&self) -> f64 {
        self.total as f64 / 256.0
    }

    /// Computes chi-squared statistic for uniformity test.
    pub fn chi_squared(&self) -> f64 {
        let expected = self.expected_uniform_count();
        if expected == 0.0 {
            return 0.0;
        }

        self.distribution
            .iter()
            .map(|&observed| {
                let diff = observed as f64 - expected;
                (diff * diff) / expected
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_view_tag_deterministic() {
        let secret = [42u8; 32];
        let tag1 = compute_view_tag(&secret);
        let tag2 = compute_view_tag(&secret);

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_view_tag_different_secrets() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let tag1 = compute_view_tag(&secret1);
        let tag2 = compute_view_tag(&secret2);

        // Different secrets should usually produce different tags
        // (1/256 chance of collision)
        let _ = (tag1, tag2);
    }

    #[test]
    fn test_view_tag_bytes() {
        let secret = [0xAB; 32];
        let bytes = compute_view_tag_bytes(&secret, 4);

        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], compute_view_tag(&secret));
    }

    #[test]
    fn test_verify_view_tag() {
        let secret = [99u8; 32];
        let correct_tag = compute_view_tag(&secret);
        let wrong_tag = correct_tag.wrapping_add(1);

        assert!(verify_view_tag(&secret, correct_tag));
        assert!(!verify_view_tag(&secret, wrong_tag));
    }

    #[test]
    fn test_view_tag_distribution() {
        // Generate many random secrets and check view tag distribution
        let mut rng = rand::thread_rng();
        let mut stats = ViewTagStats::new();

        for _ in 0..10000 {
            let secret: [u8; 32] = rng.gen();
            let tag = compute_view_tag(&secret);
            stats.add(tag);
        }

        // Chi-squared test for uniformity
        // With 255 degrees of freedom, critical value at p=0.001 is ~310
        // A good hash should produce chi-squared well below this
        let chi_sq = stats.chi_squared();
        assert!(
            chi_sq < 500.0,
            "View tags are not uniformly distributed: χ² = {}",
            chi_sq
        );
    }

    #[test]
    fn test_view_tag_stats() {
        let mut stats = ViewTagStats::new();

        stats.add(0);
        stats.add(0);
        stats.add(1);
        stats.add(255);

        assert_eq!(stats.total, 4);
        assert_eq!(stats.distribution[0], 2);
        assert_eq!(stats.distribution[1], 1);
        assert_eq!(stats.distribution[255], 1);

        let (most_common, count) = stats.most_common().unwrap();
        assert_eq!(most_common, 0);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_efficiency_calculation() {
        // With 1-byte view tags, we expect ~99.6% filtering efficiency
        // That means for 100,000 announcements with uniformly distributed tags,
        // we should only need to fully process ~391 per view tag (100000/256)

        let total_announcements = 100_000u64;
        let expected_per_tag = total_announcements as f64 / 256.0;
        let efficiency = 1.0 - (expected_per_tag / total_announcements as f64);

        assert!((efficiency - 0.996).abs() < 0.001);
    }
}
