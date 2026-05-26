//! Shared business-logic template metadata and run summary DTOs.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum BusinessLogicTemplateMutability {
    ReadOnly,
    StateChanging,
}

impl BusinessLogicTemplateMutability {
    pub fn mutates_state(self) -> bool {
        matches!(self, Self::StateChanging)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum BusinessLogicTemplateAvailability {
    Executable,
    MetadataOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct BusinessLogicTemplateMetadata {
    pub id: String,
    pub version: String,
    pub title: String,
    pub category: String,
    pub mutability: BusinessLogicTemplateMutability,
    #[serde(default)]
    pub required_roles: Vec<String>,
    pub seed_data_description: String,
    #[serde(default)]
    pub supported_route_patterns: Vec<String>,
    pub oracle_description: String,
    pub default_vuln_class: String,
    pub default_severity: String,
    pub availability: BusinessLogicTemplateAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub metadata_only_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct BusinessLogicTemplateProvenance {
    pub template_id: String,
    pub template_version: String,
    pub title: String,
    pub category: String,
    pub mutability: BusinessLogicTemplateMutability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct BusinessLogicTemplateRunRecord {
    pub run_id: String,
    pub project_id: String,
    pub template_id: String,
    pub template_version: String,
    pub generated_count: u32,
    pub skipped_count: u32,
    #[serde(default)]
    pub skip_reasons: Vec<String>,
    pub dry_run: bool,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct BusinessLogicRunSummary {
    pub run_id: String,
    pub templates_considered: u32,
    pub candidates_generated: u32,
    pub templates_skipped: u32,
    pub dry_run: bool,
    #[serde(default)]
    pub templates: Vec<BusinessLogicTemplateRunRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusinessLogicTemplateDescriptor {
    pub id: &'static str,
    pub version: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub mutability: BusinessLogicTemplateMutability,
    pub required_roles: &'static [&'static str],
    pub seed_data_description: &'static str,
    pub supported_route_patterns: &'static [&'static str],
    pub oracle_description: &'static str,
    pub default_vuln_class: &'static str,
    pub default_severity: &'static str,
    pub availability: BusinessLogicTemplateAvailability,
    pub metadata_only_reason: Option<&'static str>,
}

impl BusinessLogicTemplateDescriptor {
    pub fn metadata(self) -> BusinessLogicTemplateMetadata {
        BusinessLogicTemplateMetadata {
            id: self.id.to_string(),
            version: self.version.to_string(),
            title: self.title.to_string(),
            category: self.category.to_string(),
            mutability: self.mutability,
            required_roles: self.required_roles.iter().map(|role| (*role).to_string()).collect(),
            seed_data_description: self.seed_data_description.to_string(),
            supported_route_patterns: self
                .supported_route_patterns
                .iter()
                .map(|pattern| (*pattern).to_string())
                .collect(),
            oracle_description: self.oracle_description.to_string(),
            default_vuln_class: self.default_vuln_class.to_string(),
            default_severity: self.default_severity.to_string(),
            availability: self.availability,
            metadata_only_reason: self.metadata_only_reason.map(str::to_string),
        }
    }

    pub fn provenance(self) -> BusinessLogicTemplateProvenance {
        BusinessLogicTemplateProvenance {
            template_id: self.id.to_string(),
            template_version: self.version.to_string(),
            title: self.title.to_string(),
            category: self.category.to_string(),
            mutability: self.mutability,
        }
    }
}

pub const TENANT_OBJECT_ISOLATION_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "tenant_object_isolation",
        version: "1",
        title: "Tenant/object isolation",
        category: "authorization",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["two_distinct_non_anonymous_roles"],
        seed_data_description:
            "Create an object with a unique marker as one configured role, then reuse the captured object id as a peer role.",
        supported_route_patterns: &["POST collection route paired with GET detail route"],
        oracle_description:
            "Confirmed only when the peer role receives a 2xx response containing the seeded marker.",
        default_vuln_class: "BUSINESS_LOGIC_OBJECT_ISOLATION",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const COUPON_PRICE_MANIPULATION_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "coupon_price_manipulation",
        version: "1",
        title: "Coupon or price manipulation",
        category: "pricing",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["one_configured_role_or_anonymous"],
        seed_data_description:
            "Submit a unique coupon marker together with low controlled price, total, amount, or discount fields.",
        supported_route_patterns: &[
            "state-changing checkout, cart, coupon, payment, billing, order, invoice, price, amount, total, discount, or promo route",
        ],
        oracle_description:
            "Confirmed only when the live response is 2xx and contains the controlled coupon marker.",
        default_vuln_class: "BUSINESS_LOGIC_PRICE_MANIPULATION",
        default_severity: "Medium",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const AI_CHATBOT_EXPLOITABILITY_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "ai_chatbot_exploitability",
        version: "1",
        title: "AI chatbot exploitability",
        category: "ai",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["one_configured_role_or_anonymous"],
        seed_data_description:
            "Send a unique prompt-injection marker through a message-like request field.",
        supported_route_patterns: &[
            "state-changing AI, chat, assistant, bot, LLM, copilot, prompt, message, question, input, or query route",
        ],
        oracle_description:
            "Confirmed only when the live response contains both the marker and hidden-instruction evidence.",
        default_vuln_class: "AI_CHATBOT_PROMPT_INJECTION",
        default_severity: "Medium",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const FILE_PERMISSION_REVALIDATION_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "file_permission_revalidation",
        version: "1",
        title: "File access after permission change",
        category: "file_access",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["two_distinct_non_anonymous_roles"],
        seed_data_description:
            "Create a file-like object as one role, change access permissions with a peer marker, then verify the peer cannot still read the file marker.",
        supported_route_patterns: &[
            "POST file/document collection route paired with GET detail route and a state-changing share, permission, access, member, collaborator, revoke, or grant route",
        ],
        oracle_description:
            "Confirmed only when the peer role receives a 2xx response containing the seeded file marker after the permission-change step.",
        default_vuln_class: "BUSINESS_LOGIC_FILE_PERMISSION_BYPASS",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const WEBHOOK_CALLBACK_TRUST_BOUNDARY_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "webhook_callback_trust_boundary",
        version: "1",
        title: "Webhook/callback trust boundary",
        category: "integration_trust",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["anonymous_or_configured_role"],
        seed_data_description:
            "Submit a unique event marker and unsigned callback payload to webhook-like routes.",
        supported_route_patterns: &[
            "state-changing webhook, callback, receiver, integration, event, or notify route",
        ],
        oracle_description:
            "Confirmed only when the live response is 2xx and reflects the unsigned event marker.",
        default_vuln_class: "BUSINESS_LOGIC_WEBHOOK_TRUST_BOUNDARY",
        default_severity: "Medium",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const INVITE_ACCEPT_REUSE_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "invite_accept_reuse",
        version: "1",
        title: "Invite accept/reuse",
        category: "account_lifecycle",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["inviter_role", "invitee_role"],
        seed_data_description:
            "Create an invite with a unique marker, capture the issued invite token/id, accept it, then replay acceptance with the same token.",
        supported_route_patterns: &["invite creation route paired with invite accept/join route"],
        oracle_description:
            "Confirmed only when the replay acceptance returns 2xx and reflects the invite marker.",
        default_vuln_class: "BUSINESS_LOGIC_INVITE_REUSE",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const PASSWORD_RESET_TOKEN_REPLAY_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "password_reset_token_replay",
        version: "1",
        title: "Password reset token replay",
        category: "account_lifecycle",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["victim_account", "attacker_account"],
        seed_data_description:
            "Request a reset for a disposable victim marker, capture a reset token from the test response, submit a reset, then replay the same token.",
        supported_route_patterns: &["password reset request and reset confirmation routes"],
        oracle_description:
            "Confirmed only when the replay reset returns 2xx and reflects the reset marker.",
        default_vuln_class: "BUSINESS_LOGIC_PASSWORD_RESET_TOKEN_REPLAY",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const EMAIL_CHANGE_WITHOUT_REAUTH_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "email_change_without_reauth",
        version: "1",
        title: "Email change without reauthentication",
        category: "account_lifecycle",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["one_configured_role"],
        seed_data_description:
            "Submit a unique disposable email marker to an account/profile email-change route without a password/current-password field.",
        supported_route_patterns: &["state-changing account/profile/settings email route"],
        oracle_description:
            "Confirmed only when the response is 2xx and reflects the new email marker without reauth evidence.",
        default_vuln_class: "BUSINESS_LOGIC_EMAIL_CHANGE_WITHOUT_REAUTH",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const SUBSCRIPTION_DOWNGRADE_FEATURE_RETENTION_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "subscription_downgrade_feature_retention",
        version: "1",
        title: "Subscription downgrade feature retention",
        category: "entitlements",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["one_configured_role"],
        seed_data_description:
            "Downgrade a disposable subscription marker, then call a premium/feature route that should no longer be entitled.",
        supported_route_patterns: &[
            "state-changing subscription/plan/billing downgrade route paired with premium/feature/export/API route",
        ],
        oracle_description:
            "Confirmed only when the post-downgrade feature response is 2xx and reflects the downgrade marker.",
        default_vuln_class: "BUSINESS_LOGIC_ENTITLEMENT_RETENTION",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const REFUND_REPLAY_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "refund_replay",
        version: "1",
        title: "Refund/replay",
        category: "payments",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["one_configured_role"],
        seed_data_description:
            "Submit a refund marker once, capture a refund/order id when available, then replay the same refund request.",
        supported_route_patterns: &["state-changing refund, return, reversal, chargeback, or credit route"],
        oracle_description:
            "Confirmed only when the replay response is 2xx and reflects the refund marker.",
        default_vuln_class: "BUSINESS_LOGIC_REFUND_REPLAY",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const WEBHOOK_REPLAY_FRESHNESS_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "webhook_replay_freshness",
        version: "1",
        title: "Webhook replay/freshness",
        category: "integration_trust",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["anonymous_or_configured_role"],
        seed_data_description:
            "Send the same webhook event id and stale timestamp twice with a unique marker.",
        supported_route_patterns: &[
            "state-changing webhook, callback, receiver, integration, event, or notify route with event id/timestamp/signature fields",
        ],
        oracle_description:
            "Confirmed only when the replay response is 2xx and reflects the replay marker.",
        default_vuln_class: "BUSINESS_LOGIC_WEBHOOK_REPLAY_FRESHNESS",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const OAUTH_CALLBACK_STATE_CONFUSION_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "oauth_callback_state_confusion",
        version: "1",
        title: "OAuth callback state confusion",
        category: "account_lifecycle",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["one_configured_role_or_anonymous"],
        seed_data_description:
            "Call an OAuth/OIDC callback route with mismatched state/code markers and no prior browser session seed.",
        supported_route_patterns: &["OAuth/OIDC callback, redirect_uri, authorize callback, or SSO callback route"],
        oracle_description:
            "Confirmed only when the callback returns 2xx and reflects the mismatched state marker.",
        default_vuln_class: "BUSINESS_LOGIC_OAUTH_STATE_CONFUSION",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const CREDIT_EXHAUSTION_BYPASS_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "credit_exhaustion_bypass",
        version: "1",
        title: "Credit exhaustion bypass",
        category: "quota",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["one_configured_role"],
        seed_data_description:
            "Submit repeated credit/quota-consuming requests with the same idempotency marker and low/zero credit hints.",
        supported_route_patterns: &["state-changing credit, quota, usage, token, generation, API, or metering route"],
        oracle_description:
            "Confirmed only when the post-exhaustion replay returns 2xx and reflects the credit marker.",
        default_vuln_class: "BUSINESS_LOGIC_CREDIT_EXHAUSTION_BYPASS",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const AI_CHATBOT_INDIRECT_ACTION_ABUSE_TEMPLATE: BusinessLogicTemplateDescriptor =
    BusinessLogicTemplateDescriptor {
        id: "ai_chatbot_indirect_action_abuse",
        version: "1",
        title: "AI/chatbot indirect action abuse",
        category: "ai",
        mutability: BusinessLogicTemplateMutability::StateChanging,
        required_roles: &["one_configured_role_or_anonymous"],
        seed_data_description:
            "Send a prompt that asks the assistant to perform a harmless indirect action with a unique marker.",
        supported_route_patterns: &[
            "state-changing AI, chat, assistant, bot, LLM, copilot, agent, tool, action, message, question, input, or query route",
        ],
        oracle_description:
            "Confirmed only when the response indicates an indirect action/tool execution and reflects the marker.",
        default_vuln_class: "AI_CHATBOT_INDIRECT_ACTION_ABUSE",
        default_severity: "High",
        availability: BusinessLogicTemplateAvailability::Executable,
        metadata_only_reason: None,
    };

pub const BUSINESS_LOGIC_TEMPLATE_REGISTRY: &[BusinessLogicTemplateDescriptor] = &[
    TENANT_OBJECT_ISOLATION_TEMPLATE,
    COUPON_PRICE_MANIPULATION_TEMPLATE,
    AI_CHATBOT_EXPLOITABILITY_TEMPLATE,
    AI_CHATBOT_INDIRECT_ACTION_ABUSE_TEMPLATE,
    FILE_PERMISSION_REVALIDATION_TEMPLATE,
    WEBHOOK_CALLBACK_TRUST_BOUNDARY_TEMPLATE,
    WEBHOOK_REPLAY_FRESHNESS_TEMPLATE,
    INVITE_ACCEPT_REUSE_TEMPLATE,
    PASSWORD_RESET_TOKEN_REPLAY_TEMPLATE,
    EMAIL_CHANGE_WITHOUT_REAUTH_TEMPLATE,
    SUBSCRIPTION_DOWNGRADE_FEATURE_RETENTION_TEMPLATE,
    REFUND_REPLAY_TEMPLATE,
    OAUTH_CALLBACK_STATE_CONFUSION_TEMPLATE,
    CREDIT_EXHAUSTION_BYPASS_TEMPLATE,
];

pub fn business_logic_template_metadata() -> Vec<BusinessLogicTemplateMetadata> {
    BUSINESS_LOGIC_TEMPLATE_REGISTRY.iter().map(|template| template.metadata()).collect()
}

pub fn business_logic_template_by_id(id: &str) -> Option<&'static BusinessLogicTemplateDescriptor> {
    BUSINESS_LOGIC_TEMPLATE_REGISTRY.iter().find(|template| template.id == id)
}
