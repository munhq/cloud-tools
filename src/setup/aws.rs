use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;

use crate::clouds::aws::auth::assume_role;

/// Role deployed in the customer's AWS management account.
const ROLE_NAME: &str = "MunbotFinOpsRole";


/// Management account CloudFormation template.
/// Served at GET /setup/aws/cloudformation.yaml
/// Deployed by the customer in their AWS MANAGEMENT account (org root).
pub const CLOUDFORMATION_TEMPLATE: &str = r#"AWSTemplateFormatVersion: '2010-09-09'
Description: >
  Munbot FinOps - Organisation-level read-only access.
  Deploy this stack in your AWS MANAGEMENT (root/payer) account.
  It creates one IAM role Munbot uses to read costs and inventory
  across your entire AWS Organisation. No credentials are ever shared.

Parameters:
  TrustedArn:
    Type: String
    Description: Munbot platform identity ARN allowed to assume this role.
  ExternalId:
    Type: String
    Description: Unique external ID for your organisation (provided by Munbot).

Resources:
  MunbotFinOpsRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: MunbotFinOpsRole
      Description: >
        Munbot FinOps read-only role — organisation-level cost and resource analysis.
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Ref TrustedArn
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      Policies:
        - PolicyName: MunbotFinOpsOrgReadOnly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Sid: CostExplorerOrgWide
                Effect: Allow
                Action:
                  - ce:GetCostAndUsage
                  - ce:GetCostForecast
                  - ce:GetDimensionValues
                  - ce:GetTags
                Resource: '*'
              - Sid: OrganisationsReadOnly
                Effect: Allow
                Action:
                  - organizations:ListAccounts
                  - organizations:ListAccountsForParent
                  - organizations:DescribeOrganization
                  - organizations:ListOrganizationalUnitsForParent
                  - organizations:ListRoots
                Resource: '*'
              - Sid: AssumeIntoMemberAccounts
                Effect: Allow
                Action:
                  - sts:AssumeRole
                Resource: !Sub 'arn:aws:iam::*:role/${MemberRoleName}'
              - Sid: ManagementAccountInventory
                Effect: Allow
                Action:
                  - ec2:DescribeInstances
                  - ec2:DescribeVolumes
                  - ec2:DescribeAddresses
                  - ec2:DescribeRegions
                  - ec2:DescribeInstanceTypes
                  - ec2:DescribeNatGateways
                  - ec2:DescribeSnapshots
                  - ec2:DescribeImages
                  - ec2:DescribeKeyPairs
                  - ec2:DescribeReservedInstances
                  - cloudwatch:GetMetricStatistics
                  - cloudwatch:ListMetrics
                  - logs:DescribeLogGroups
                  - rds:DescribeDBInstances
                  - rds:DescribeDBClusters
                  - elasticloadbalancing:DescribeLoadBalancers
                  - elasticloadbalancing:DescribeTargetGroups
                  - elasticloadbalancing:DescribeTargetHealth
                  - s3:ListAllMyBuckets
                  - s3:GetBucketLocation
                  - s3:GetBucketLifecycleConfiguration
                  - s3:ListBucketMultipartUploads
                Resource: '*'

  MemberRoleName:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /munbot/member-role-name
      Type: String
      Value: MunbotFinOpsMemberRole
      Description: Name of the member-account role deployed via StackSet.

Outputs:
  RoleArn:
    Description: Management account Munbot FinOps role ARN
    Value: !GetAtt MunbotFinOpsRole.Arn
  MemberStackSetTemplate:
    Description: >
      To enable per-account resource inventory, deploy the member-account
      StackSet from: <CLOUD_TOOLS_PUBLIC_URL>/setup/aws/member-cloudformation.yaml
      This is optional — org-wide cost data works without it.
    Value: !Sub 'Deploy MunbotFinOpsMemberRole via StackSet to all accounts in your org'
"#;

/// Member account StackSet template.
/// Deployed via CloudFormation StackSets to ALL accounts in the org.
/// Trusts the management account MunbotFinOpsRole so bot can assume in.
pub const MEMBER_CLOUDFORMATION_TEMPLATE: &str = r#"AWSTemplateFormatVersion: '2010-09-09'
Description: >
  Munbot FinOps - Member account role.
  Deploy this as a StackSet from your management account to all org accounts.
  It trusts the management account MunbotFinOpsRole so Munbot can pull
  per-account EC2, RDS, and CloudWatch data.

Parameters:
  ManagementAccountId:
    Type: String
    Description: Your AWS Management Account ID (12 digits).

Resources:
  MunbotFinOpsMemberRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: MunbotFinOpsMemberRole
      Description: Munbot FinOps member-account read-only role.
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${ManagementAccountId}:role/MunbotFinOpsRole'
            Action: sts:AssumeRole
      Policies:
        - PolicyName: MunbotFinOpsMemberReadOnly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - ec2:DescribeInstances
                  - ec2:DescribeVolumes
                  - ec2:DescribeAddresses
                  - ec2:DescribeRegions
                  - ec2:DescribeInstanceTypes
                  - ec2:DescribeNatGateways
                  - ec2:DescribeSnapshots
                  - ec2:DescribeImages
                  - ec2:DescribeKeyPairs
                  - ec2:DescribeReservedInstances
                  - cloudwatch:GetMetricStatistics
                  - cloudwatch:ListMetrics
                  - logs:DescribeLogGroups
                  - rds:DescribeDBInstances
                  - rds:DescribeDBClusters
                  - elasticloadbalancing:DescribeLoadBalancers
                  - elasticloadbalancing:DescribeTargetGroups
                  - elasticloadbalancing:DescribeTargetHealth
                  - s3:ListAllMyBuckets
                  - s3:GetBucketLocation
                  - s3:GetBucketLifecycleConfiguration
                  - s3:ListBucketMultipartUploads
                Resource: '*'

Outputs:
  RoleArn:
    Value: !GetAtt MunbotFinOpsMemberRole.Arn
"#;

// ── Public types ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct InitiateResponse {
    /// Management account ID provided by the customer
    pub management_account_id: String,
    /// Unique per org — included in the trust policy condition
    pub external_id: String,
    /// Management account role ARN — stored automatically, customer never copies this
    pub role_arn: String,
    /// Step 1: Deploy management account stack (org-wide CE + inventory)
    pub launch_url: String,
    /// Step 2 (optional): Deploy member StackSet for per-account inventory
    pub member_stackset_url: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub connected: bool,
    pub management_account_id: String,
    pub role_arn: String,
    /// Number of accounts in the org, if visible
    pub org_account_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── Business logic ─────────────────────────────────────────────────────────────

/// Generate the onboarding artefacts for a customer AWS organisation.
/// Takes the management (root/payer) account ID.
/// Does NOT make any AWS API calls — purely constructs the launch URLs.
pub fn initiate(management_account_id: &str) -> Result<InitiateResponse> {
    let platform_arn = std::env::var("PLATFORM_AWS_ARN")
        .context("PLATFORM_AWS_ARN not set — set to your platform IAM user/role ARN")?;
    let public_url = std::env::var("CLOUD_TOOLS_PUBLIC_URL")
        .context("CLOUD_TOOLS_PUBLIC_URL not set — set to your cloud-tools public HTTPS URL")?;
    let public_url = public_url.trim_end_matches('/');

    let external_id = format!("munbot-{management_account_id}");
    let role_arn = format!("arn:aws:iam::{management_account_id}:role/{ROLE_NAME}");

    let template_url = format!("{public_url}/setup/aws/cloudformation.yaml");
    let member_template_url = format!("{public_url}/setup/aws/member-cloudformation.yaml");

    let launch_url = format!(
        "https://console.aws.amazon.com/cloudformation/home?region=us-east-1\
         #/stacks/create/review\
         ?templateURL={t}\
         &stackName=MunbotFinOps\
         &param_TrustedArn={a}\
         &param_ExternalId={e}",
        t = urlencoding::encode(&template_url),
        a = urlencoding::encode(&platform_arn),
        e = urlencoding::encode(&external_id),
    );

    // StackSet URL for member accounts — customer deploys this after the management stack
    let member_stackset_url = format!(
        "https://console.aws.amazon.com/cloudformation/home?region=us-east-1\
         #/stacksets/create\
         ?templateURL={t}\
         &stackSetName=MunbotFinOpsMember\
         &param_ManagementAccountId={id}",
        t = urlencoding::encode(&member_template_url),
        id = urlencoding::encode(management_account_id),
    );

    Ok(InitiateResponse {
        management_account_id: management_account_id.to_string(),
        external_id,
        role_arn,
        launch_url,
        member_stackset_url,
    })
}

/// Verify by attempting STS AssumeRole on the management account role.
/// If successful, also enumerates org accounts so we know scope.
pub async fn verify(http: &Client, management_account_id: &str) -> VerifyResponse {
    let external_id = format!("munbot-{management_account_id}");
    let role_arn = format!("arn:aws:iam::{management_account_id}:role/{ROLE_NAME}");

    match assume_role(http, &role_arn, Some(&external_id)).await {
        Ok(creds) => {
            // Try to enumerate org accounts to confirm org-level access
            let org_account_count =
                crate::clouds::aws::organizations::list_accounts(http, &creds)
                    .await
                    .ok()
                    .map(|accounts| accounts.len());

            VerifyResponse {
                connected: true,
                management_account_id: management_account_id.to_string(),
                role_arn,
                org_account_count,
                error: None,
            }
        }
        Err(e) => VerifyResponse {
            connected: false,
            management_account_id: management_account_id.to_string(),
            role_arn,
            org_account_count: None,
            error: Some(e.to_string()),
        },
    }
}
