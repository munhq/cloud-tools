/// Hardcoded on-demand pricing for common instance types and storage.
/// Source: AWS pricing pages, us-east-1 / eu-west-1 (Linux, no reserved).
/// Used for cost estimation when Cost Explorer data isn't available.

pub const HOURS_PER_MONTH: f64 = 730.0;

/// On-demand hourly price in USD for common EC2 instance types (us-east-1, Linux).
pub fn ec2_hourly(instance_type: &str) -> Option<f64> {
    let price = match instance_type {
        // t3 family
        "t3.nano"     => 0.0052,
        "t3.micro"    => 0.0104,
        "t3.small"    => 0.0208,
        "t3.medium"   => 0.0416,
        "t3.large"    => 0.0832,
        "t3.xlarge"   => 0.1664,
        "t3.2xlarge"  => 0.3328,
        // t3a family
        "t3a.nano"    => 0.0047,
        "t3a.micro"   => 0.0094,
        "t3a.small"   => 0.0188,
        "t3a.medium"  => 0.0376,
        "t3a.large"   => 0.0752,
        // m5 family
        "m5.large"    => 0.096,
        "m5.xlarge"   => 0.192,
        "m5.2xlarge"  => 0.384,
        "m5.4xlarge"  => 0.768,
        "m5.8xlarge"  => 1.536,
        // m6i family
        "m6i.large"   => 0.096,
        "m6i.xlarge"  => 0.192,
        "m6i.2xlarge" => 0.384,
        "m6i.4xlarge" => 0.768,
        // c5 family
        "c5.large"    => 0.085,
        "c5.xlarge"   => 0.170,
        "c5.2xlarge"  => 0.340,
        "c5.4xlarge"  => 0.680,
        // c6i family
        "c6i.large"   => 0.085,
        "c6i.xlarge"  => 0.170,
        "c6i.2xlarge" => 0.340,
        // r5 family
        "r5.large"    => 0.126,
        "r5.xlarge"   => 0.252,
        "r5.2xlarge"  => 0.504,
        "r5.4xlarge"  => 1.008,
        // r6i family
        "r6i.large"   => 0.126,
        "r6i.xlarge"  => 0.252,
        "r6i.2xlarge" => 0.504,
        // c3 family (previous gen — upgrade candidate)
        "c3.standard-4" => 0.168,
        _ => return None,
    };
    Some(price)
}

/// Monthly cost per GB for EBS volume types (us-east-1).
pub fn ebs_gb_per_month(volume_type: &str) -> f64 {
    match volume_type {
        "gp3"      => 0.08,
        "gp2"      => 0.10,  // 25% more expensive than gp3
        "io1"      => 0.125,
        "io2"      => 0.125,
        "st1"      => 0.045,
        "sc1"      => 0.015,
        "standard" => 0.05,
        _          => 0.10,  // fallback to gp2 price
    }
}

/// Monthly cost for an unattached Elastic IP.
pub fn eip_monthly() -> f64 {
    0.005 * HOURS_PER_MONTH  // $3.65/month
}

/// Monthly on-demand price for RDS instance classes (us-east-1, single-AZ, MySQL/Postgres).
pub fn rds_hourly(instance_class: &str) -> Option<f64> {
    let price = match instance_class {
        "db.t3.micro"   => 0.017,
        "db.t3.small"   => 0.034,
        "db.t3.medium"  => 0.068,
        "db.t3.large"   => 0.136,
        "db.t3.xlarge"  => 0.272,
        "db.t3.2xlarge" => 0.544,
        "db.m5.large"   => 0.171,
        "db.m5.xlarge"  => 0.342,
        "db.m5.2xlarge" => 0.684,
        "db.m6g.large"  => 0.162,
        "db.m6g.xlarge" => 0.324,
        "db.r5.large"   => 0.240,
        "db.r5.xlarge"  => 0.480,
        "db.r5.2xlarge" => 0.960,
        "db.r6g.large"  => 0.228,
        "db.r6g.xlarge" => 0.456,
        _ => return None,
    };
    Some(price)
}

/// Previous-generation EC2 instance families — flag for upgrade.
pub const PREV_GEN_FAMILIES: &[&str] = &[
    "t1", "t2", "m1", "m2", "m3", "m4",
    "c1", "c3", "c4", "r3", "r4",
    "i2", "hs1", "g2",
];

pub fn is_prev_gen(instance_type: &str) -> bool {
    let family = instance_type.split('.').next().unwrap_or("");
    PREV_GEN_FAMILIES.contains(&family)
}

/// Estimate monthly cost for an EC2 instance. Returns None if type unknown.
pub fn ec2_monthly(instance_type: &str) -> Option<f64> {
    ec2_hourly(instance_type).map(|h| h * HOURS_PER_MONTH)
}

/// Estimate monthly cost for an EBS volume.
pub fn ebs_monthly(size_gb: u64, volume_type: &str) -> f64 {
    size_gb as f64 * ebs_gb_per_month(volume_type)
}

/// Estimate monthly cost for an RDS instance (single-AZ).
pub fn rds_monthly(instance_class: &str) -> Option<f64> {
    rds_hourly(instance_class).map(|h| h * HOURS_PER_MONTH)
}

/// Savings from upgrading a gp2 volume to gp3 (same size).
pub fn gp2_to_gp3_savings(size_gb: u64) -> f64 {
    let gp2_cost = ebs_monthly(size_gb, "gp2");
    let gp3_cost = ebs_monthly(size_gb, "gp3");
    gp2_cost - gp3_cost
}

/// Monthly cost for an EBS snapshot (per GB stored, us-east-1).
pub fn snapshot_monthly(size_gb: u64) -> f64 {
    size_gb as f64 * 0.05 // $0.05/GB-month for standard snapshots
}

/// Estimated monthly cost for storing an AMI (sum of its backing snapshot sizes).
pub fn ami_snapshot_monthly(total_snapshot_gb: u64) -> f64 {
    snapshot_monthly(total_snapshot_gb)
}

/// Estimated monthly cost for an ALB (us-east-1, base hourly charge only).
pub fn alb_monthly() -> f64 {
    0.0225 * HOURS_PER_MONTH // ~$16.43/month base charge
}

/// Estimated monthly cost for an NLB (us-east-1, base hourly charge only).
pub fn nlb_monthly() -> f64 {
    0.0225 * HOURS_PER_MONTH // ~$16.43/month base charge
}

/// Monthly LB cost based on type.
pub fn lb_monthly(lb_type: &str) -> f64 {
    match lb_type {
        "application" => alb_monthly(),
        "network" => nlb_monthly(),
        "gateway" => 0.0125 * HOURS_PER_MONTH,
        _ => alb_monthly(), // fallback to ALB pricing
    }
}

/// Monthly base charge for a NAT gateway (us-east-1) — excludes data processing fees.
/// Data processing is billed separately at $0.045/GB but negligible for idle gateways.
pub fn nat_gateway_monthly() -> f64 {
    0.045 * HOURS_PER_MONTH // ~$32.85/month base charge
}

/// Estimated monthly cost for CloudWatch Log storage (per GB, us-east-1).
pub fn cloudwatch_log_storage_monthly(stored_bytes: u64) -> f64 {
    let gb = stored_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    gb * 0.03 // $0.03/GB-month for standard log storage
}
