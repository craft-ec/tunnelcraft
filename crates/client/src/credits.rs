//! Subscription and usage tracking for local consumption
//!
//! Tracks local bandwidth consumption and subscription status.
//! In the per-user pool model, users subscribe and relays earn from the pool.
//! This module tracks estimated local usage to display to the user.
//!
//! ## Design
//!
//! - Subscription tier determines bandwidth allocation
//! - Local consumption is tracked per-request for UI display
//! - Cost estimation is based on shards * hops
//! - Post-epoch, actual usage is reconciled via ForwardReceipts
//!
//! ## Usage
//!
//! ```ignore
//! let mut manager = CreditManager::new();
//!
//! // Before each request, estimate cost
//! let estimated = manager.estimate_request_cost(payload_size, hops);
//! if manager.can_afford(estimated) {
//!     manager.reserve(request_id, estimated);
//!     // ... send request ...
//!     manager.confirm_consumed(&request_id, actual_cost);
//! }
//! ```

use std::collections::HashMap;
use tunnelcraft_core::{Id, SubscriptionTier};
use tunnelcraft_erasure::TOTAL_SHARDS;

/// Cost per shard per hop (in credit units)
const COST_PER_SHARD_HOP: u64 = 1;

/// Base cost per request (overhead)
const BASE_REQUEST_COST: u64 = 5;

/// Credit Manager for tracking local usage
#[derive(Debug)]
pub struct CreditManager {
    /// Current subscription tier (None if unsubscribed)
    subscription_tier: Option<SubscriptionTier>,
    /// Total budget for current subscription period (in credit units)
    budget: u64,
    /// Total consumed credits in this period
    consumed: u64,
    /// Reserved credits (pending confirmation)
    reserved: u64,
    /// Per-request reserved amounts
    reservations: HashMap<Id, u64>,
}

impl Default for CreditManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CreditManager {
    /// Create a new credit manager
    pub fn new() -> Self {
        Self {
            subscription_tier: None,
            budget: 0,
            consumed: 0,
            reserved: 0,
            reservations: HashMap::new(),
        }
    }

    /// Set subscription status
    pub fn set_subscription(&mut self, tier: SubscriptionTier, budget: u64) {
        self.subscription_tier = Some(tier);
        self.budget = budget;
        self.consumed = 0;
        self.reserved = 0;
        self.reservations.clear();
    }

    /// Check if user has an active subscription
    pub fn is_subscribed(&self) -> bool {
        self.subscription_tier.is_some()
    }

    /// Get subscription tier
    pub fn subscription_tier(&self) -> Option<SubscriptionTier> {
        self.subscription_tier
    }

    /// Get total budget
    pub fn total_balance(&self) -> u64 {
        self.budget
    }

    /// Get available credits (budget - consumed - reserved)
    pub fn available_credits(&self) -> u64 {
        self.budget.saturating_sub(self.consumed).saturating_sub(self.reserved)
    }

    /// Get consumed credits
    pub fn consumed_credits(&self) -> u64 {
        self.consumed
    }

    /// Get reserved credits
    pub fn reserved_credits(&self) -> u64 {
        self.reserved
    }

    /// Estimate cost for a request
    ///
    /// Cost = base + (shards * hops * cost_per_shard_hop)
    pub fn estimate_request_cost(&self, _payload_size: usize, hops: u8) -> u64 {
        let shard_cost = (TOTAL_SHARDS as u64) * (hops as u64) * COST_PER_SHARD_HOP;
        BASE_REQUEST_COST + shard_cost
    }

    /// Check if we can afford a given cost
    pub fn can_afford(&self, cost: u64) -> bool {
        self.available_credits() >= cost
    }

    /// Reserve credits for a pending request
    ///
    /// Returns false if insufficient credits
    pub fn reserve(&mut self, request_id: Id, amount: u64) -> bool {
        if !self.can_afford(amount) {
            return false;
        }
        self.reserved += amount;
        self.reservations.insert(request_id, amount);
        true
    }

    /// Confirm consumption of reserved credits
    pub fn confirm_consumed(&mut self, request_id: &Id, actual_cost: u64) {
        if let Some(reserved) = self.reservations.remove(request_id) {
            self.reserved = self.reserved.saturating_sub(reserved);
            self.consumed += actual_cost;
        } else {
            self.consumed += actual_cost;
        }
    }

    /// Cancel a reservation (request failed/cancelled)
    pub fn cancel_reservation(&mut self, request_id: &Id) {
        if let Some(reserved) = self.reservations.remove(request_id) {
            self.reserved = self.reserved.saturating_sub(reserved);
        }
    }

    /// Get percentage of credits used
    pub fn usage_percentage(&self) -> f64 {
        let total = self.total_balance();
        if total == 0 {
            return 0.0;
        }
        let used = self.consumed + self.reserved;
        (used as f64 / total as f64) * 100.0
    }

    /// Check if credits are running low (>80% used)
    pub fn is_low(&self) -> bool {
        self.usage_percentage() > 80.0
    }

    /// Check if credits are critically low (>95% used)
    pub fn is_critical(&self) -> bool {
        self.usage_percentage() > 95.0
    }

    /// Reset consumption tracking (e.g., for new subscription period)
    pub fn reset(&mut self) {
        self.consumed = 0;
        self.reserved = 0;
        self.reservations.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_manager() {
        let manager = CreditManager::new();
        assert_eq!(manager.total_balance(), 0);
        assert_eq!(manager.available_credits(), 0);
        assert!(!manager.is_subscribed());
    }

    #[test]
    fn test_set_subscription() {
        let mut manager = CreditManager::new();
        manager.set_subscription(SubscriptionTier::Standard, 1000);

        assert_eq!(manager.total_balance(), 1000);
        assert_eq!(manager.available_credits(), 1000);
        assert!(manager.is_subscribed());
        assert_eq!(manager.subscription_tier(), Some(SubscriptionTier::Standard));
    }

    #[test]
    fn test_estimate_request_cost() {
        let manager = CreditManager::new();

        // 5 shards, 2 hops: base(5) + 5*2*1 = 15
        let cost = manager.estimate_request_cost(1024, 2);
        assert_eq!(cost, 15);

        // 5 shards, 4 hops: base(5) + 5*4*1 = 25
        let cost = manager.estimate_request_cost(1024, 4);
        assert_eq!(cost, 25);
    }

    #[test]
    fn test_can_afford() {
        let mut manager = CreditManager::new();
        manager.set_subscription(SubscriptionTier::Basic, 100);

        assert!(manager.can_afford(50));
        assert!(manager.can_afford(100));
        assert!(!manager.can_afford(101));
    }

    #[test]
    fn test_reserve_and_confirm() {
        let mut manager = CreditManager::new();
        manager.set_subscription(SubscriptionTier::Basic, 100);

        let request_id = [1u8; 32];

        // Reserve 30 credits
        assert!(manager.reserve(request_id, 30));
        assert_eq!(manager.available_credits(), 70);
        assert_eq!(manager.reserved_credits(), 30);

        // Confirm consumption (actual was 25)
        manager.confirm_consumed(&request_id, 25);
        assert_eq!(manager.available_credits(), 75);
        assert_eq!(manager.reserved_credits(), 0);
        assert_eq!(manager.consumed_credits(), 25);
    }

    #[test]
    fn test_cancel_reservation() {
        let mut manager = CreditManager::new();
        manager.set_subscription(SubscriptionTier::Basic, 100);

        let request_id = [1u8; 32];

        manager.reserve(request_id, 30);
        assert_eq!(manager.available_credits(), 70);

        manager.cancel_reservation(&request_id);
        assert_eq!(manager.available_credits(), 100);
        assert_eq!(manager.reserved_credits(), 0);
    }

    #[test]
    fn test_insufficient_credits() {
        let mut manager = CreditManager::new();
        manager.set_subscription(SubscriptionTier::Basic, 50);

        let request_id = [1u8; 32];

        assert!(!manager.reserve(request_id, 60));
        assert_eq!(manager.reserved_credits(), 0);
    }

    #[test]
    fn test_usage_percentage() {
        let mut manager = CreditManager::new();
        manager.set_subscription(SubscriptionTier::Standard, 100);

        assert_eq!(manager.usage_percentage(), 0.0);

        let request_id = [1u8; 32];
        manager.reserve(request_id, 50);
        assert_eq!(manager.usage_percentage(), 50.0);

        manager.confirm_consumed(&request_id, 50);
        assert_eq!(manager.usage_percentage(), 50.0);
    }

    #[test]
    fn test_low_credits_warning() {
        let mut manager = CreditManager::new();
        manager.set_subscription(SubscriptionTier::Premium, 100);

        manager.consumed = 75;
        assert!(!manager.is_low());

        manager.consumed = 85;
        assert!(manager.is_low());
        assert!(!manager.is_critical());

        manager.consumed = 96;
        assert!(manager.is_critical());
    }

    #[test]
    fn test_reset() {
        let mut manager = CreditManager::new();
        manager.set_subscription(SubscriptionTier::Basic, 100);

        manager.consumed = 30;
        manager.reserved = 20;
        manager.reservations.insert([1u8; 32], 20);

        manager.reset();

        assert_eq!(manager.consumed_credits(), 0);
        assert_eq!(manager.reserved_credits(), 0);
        assert_eq!(manager.available_credits(), 100);
    }
}
