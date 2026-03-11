use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

/// A single cost line item — same shape regardless of which cloud produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEntry {
    pub service: String,
    pub amount_usd: f64,
    /// Inclusive start of the billing period.
    pub period_start: NaiveDate,
    /// Exclusive end of the billing period (AWS CE convention).
    pub period_end: NaiveDate,
}

/// A cloud resource from any provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub name: Option<String>,
    pub resource_type: String,
    pub region: String,
    pub status: ResourceStatus,
    pub monthly_cost_usd: Option<f64>,
    /// Provider-specific metadata (instance type, disk size, etc.)
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceStatus {
    Running,
    Stopped,
    Idle,
    Orphaned,
}

/// A utilisation metric series for a single resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSeries {
    pub resource_id: String,
    pub metric: String,
    pub unit: String,
    pub datapoints: Vec<Datapoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Datapoint {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub value: f64,
}
