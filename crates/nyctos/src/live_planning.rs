use std::collections::BTreeMap;

use nyctos_core::store::PentestCandidateRecord;
use nyctos_types::live_plan::{
    AuthRoleCapability, AuthRolePairCapability, AuthzObjectOwnershipPlan, AuthzOracle,
    AuthzOwnedObject, BrowserOracle, BrowserStep, BrowserWorkflowPlan, DifferentialHttpPlan,
    DifferentialOracle, EnvCapabilityReport, EnvCapabilityStatus, HttpOracle, HttpWorkflowPlan,
    HttpWorkflowStepPurpose, LiveHttpRequest, LiveTestPlan, NoPlanReason, NoPlanReasonCode,
    OwnedObjectCapability, SingleHttpPlan, StatefulFixtureRecipe,
};
use nyctos_types::payload::{ContextualPayload, PayloadTransport};
use nyctos_types::product::{ApiClientCallModel, RouteModel, RouteModelEndpoint};
use nyctos_types::project::{
    ProjectAuthMode, ProjectAuthOwnedObject, ProjectAuthProfile, ProjectOtpSourceKind,
};
use regex::Regex;

use crate::auth_sessions::AuthRoleBroker;
use crate::pentest_tools;

#[derive(Debug, Clone)]
pub struct LiveTestPlanSynthesisContext<'a> {
    pub route_model: Option<&'a RouteModel>,
    pub target_urls: &'a [String],
    pub auth_profiles: &'a [ProjectAuthProfile],
    pub browser_checks_enabled: bool,
    pub allow_state_changing: bool,
    pub capabilities: Option<&'a EnvCapabilityReport>,
}

#[derive(Debug, Clone)]
pub struct EnvCapabilityDiscoveryInput<'a> {
    pub target_urls: &'a [String],
    pub auth_profiles: &'a [ProjectAuthProfile],
    pub auth_env_overrides: &'a BTreeMap<String, String>,
    pub browser_checks_enabled: bool,
    pub browser_available: bool,
    pub seed_supported: bool,
    pub reset_supported: bool,
    pub exploit_mode_enabled: bool,
    pub allow_state_changing: bool,
    pub dry_run: bool,
}

pub fn discover_env_capabilities(input: EnvCapabilityDiscoveryInput<'_>) -> EnvCapabilityReport {
    let browser = if !input.browser_checks_enabled {
        EnvCapabilityStatus::Disabled
    } else if input.browser_available {
        EnvCapabilityStatus::Available
    } else {
        EnvCapabilityStatus::Missing
    };
    let state_changing = if input.allow_state_changing {
        EnvCapabilityStatus::Available
    } else if input.exploit_mode_enabled {
        EnvCapabilityStatus::Blocked
    } else {
        EnvCapabilityStatus::Disabled
    };
    let auth_roles = input
        .auth_profiles
        .iter()
        .map(|profile| auth_role_capability(profile, input.auth_env_overrides, &browser))
        .collect::<Vec<_>>();
    let usable_auth_role_pairs = auth_role_pair_capabilities(input.auth_profiles, &auth_roles);
    let owned_objects = input
        .auth_profiles
        .iter()
        .flat_map(|profile| {
            profile.owned_objects.iter().map(|object| OwnedObjectCapability {
                role: profile.role.clone(),
                name: object.name.clone(),
                id: object.id.clone(),
                route: object.route.clone(),
                marker: object.marker.clone(),
            })
        })
        .collect::<Vec<_>>();
    let mailbox = if input.auth_profiles.iter().any(|profile| {
        profile.otp_source.as_ref().is_some_and(|otp| {
            otp.kind == ProjectOtpSourceKind::Mailbox && otp.mailbox_url.is_some()
        })
    }) {
        EnvCapabilityStatus::Available
    } else {
        EnvCapabilityStatus::Missing
    };
    let mut findings = Vec::new();
    if input.target_urls.is_empty() {
        findings.push("no target URL configured for live verification".to_string());
    }
    for role in &auth_roles {
        if !role.ready() {
            findings.push(format!(
                "auth role `{}` is not ready: {}",
                role.role,
                role.notes.first().cloned().unwrap_or_else(|| "setup missing".to_string())
            ));
        }
    }
    if input.browser_checks_enabled && !input.browser_available {
        findings
            .push("browser checks are enabled but Playwright/runtime is unavailable".to_string());
    }
    if !input.allow_state_changing {
        findings.push(
            "state-changing live probes are blocked unless exploit mode and allow_state_changing_live_probes are both enabled"
                .to_string(),
        );
    }
    EnvCapabilityReport {
        target_reachable: if input.target_urls.is_empty() {
            EnvCapabilityStatus::Missing
        } else {
            EnvCapabilityStatus::Available
        },
        target_urls: input.target_urls.to_vec(),
        browser,
        seed: if input.seed_supported {
            EnvCapabilityStatus::Available
        } else {
            EnvCapabilityStatus::Missing
        },
        reset: if input.reset_supported {
            EnvCapabilityStatus::Available
        } else {
            EnvCapabilityStatus::Missing
        },
        mailbox,
        state_changing,
        exploit_mode_enabled: input.exploit_mode_enabled,
        dry_run: input.dry_run,
        auth_roles,
        usable_auth_role_pairs,
        owned_objects,
        findings,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointCandidate {
    method: String,
    path: String,
    url: String,
    state_changing: bool,
    params: Vec<String>,
    body_fields: Vec<String>,
    source: String,
}

impl EndpointCandidate {
    fn is_read_only(&self) -> bool {
        !self.state_changing && matches!(self.method.as_str(), "GET" | "HEAD" | "OPTIONS")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LivePlanStrategy {
    TrustedHeaderAuthBypass,
    AuthBypassProtectedEndpoint,
    IdorObjectIsolation,
    Csrf,
    DomXss,
    DebugExposure,
    OpenRedirect,
    CorsMisconfiguration,
    PathTraversal,
    SsrfUrlFetch,
    StatefulLifecycleRecipe,
    WebhookTrustReviewOnly,
    FileUploadReviewOnly,
    BusinessLogicReviewOnly,
    CommandInjection,
    SqlInjection,
    DependencyReviewOnly,
    GenericReviewOnly,
}

pub struct LiveTestPlanSynthesizer<'a> {
    ctx: LiveTestPlanSynthesisContext<'a>,
}

impl<'a> LiveTestPlanSynthesizer<'a> {
    pub fn new(ctx: LiveTestPlanSynthesisContext<'a>) -> Self {
        Self { ctx }
    }

    pub fn synthesize(&self, candidate: &PentestCandidateRecord) -> LiveTestPlan {
        self.synthesize_avoiding_urls(candidate, &[])
    }

    fn synthesize_avoiding_urls(
        &self,
        candidate: &PentestCandidateRecord,
        avoided_urls: &[String],
    ) -> LiveTestPlan {
        if self.ctx.target_urls.is_empty() {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::TargetOutOfScope,
                "no target base URL is available for live verification",
            );
        }
        let strategy = classify_strategy(candidate);
        if let Some(plan) = self.no_plan_for_missing_capability(candidate, strategy) {
            return plan;
        }
        let mut endpoints = infer_endpoints(candidate, self.ctx.route_model, self.ctx.target_urls);
        if !avoided_urls.is_empty() {
            endpoints.retain(|endpoint| !avoided_urls.iter().any(|url| url == &endpoint.url));
        }
        match strategy {
            LivePlanStrategy::TrustedHeaderAuthBypass => {
                self.trusted_header_auth_bypass(candidate, &endpoints)
            }
            LivePlanStrategy::AuthBypassProtectedEndpoint => self.auth_bypass(candidate, &endpoints),
            LivePlanStrategy::IdorObjectIsolation => self.idor(candidate, &endpoints),
            LivePlanStrategy::Csrf => self.csrf(candidate, &endpoints),
            LivePlanStrategy::DomXss => self.dom_xss(candidate, &endpoints),
            LivePlanStrategy::DebugExposure => self.debug_exposure(candidate, &endpoints),
            LivePlanStrategy::OpenRedirect => self.open_redirect(candidate, &endpoints),
            LivePlanStrategy::CorsMisconfiguration => self.cors_misconfiguration(candidate, &endpoints),
            LivePlanStrategy::PathTraversal => self.path_traversal(candidate, &endpoints),
            LivePlanStrategy::SsrfUrlFetch => self.no_plan(
                candidate,
                NoPlanReasonCode::UnsafeProbe,
                "SSRF-style URL fetch needs an in-scope callback or seeded local target before Nyctos can safely verify it",
            ),
            LivePlanStrategy::StatefulLifecycleRecipe => {
                self.stateful_lifecycle_recipe(candidate, &endpoints)
            }
            LivePlanStrategy::WebhookTrustReviewOnly => self.no_plan(
                candidate,
                NoPlanReasonCode::UnsafeProbe,
                "webhook trust-boundary probes need a seeded harmless event fixture; Nyctos will not send synthetic state-changing callbacks by default",
            ),
            LivePlanStrategy::FileUploadReviewOnly => self.no_plan(
                candidate,
                NoPlanReasonCode::StateChangingBlocked,
                "file upload/import probes are state-changing and need an explicit seeded upload harness before live verification",
            ),
            LivePlanStrategy::BusinessLogicReviewOnly => self.no_plan(
                candidate,
                NoPlanReasonCode::UnsafeProbe,
                "credits/payment/business-logic probes are review-only until disposable seeded state is configured; Nyctos will not mutate customer or payment data",
            ),
            LivePlanStrategy::CommandInjection => self.no_plan(
                candidate,
                NoPlanReasonCode::UnsafeProbe,
                "command-injection probes are review-only until an explicit safe harness or exploit opt-in is available",
            ),
            LivePlanStrategy::SqlInjection => self.no_plan(
                candidate,
                NoPlanReasonCode::WeakOracle,
                "SQL injection candidate lacks a safe route-specific differential oracle or seeded data marker",
            ),
            LivePlanStrategy::DependencyReviewOnly => self.no_plan(
                candidate,
                NoPlanReasonCode::DependencyReviewOnly,
                "dependency/tool findings are review-only unless a meaningful live exploit plan can be tied to a route",
            ),
            LivePlanStrategy::GenericReviewOnly => self.no_plan(
                candidate,
                NoPlanReasonCode::UnsupportedClass,
                "no route/auth/context-aware live strategy matched this candidate",
            ),
        }
    }

    fn no_plan_for_missing_capability(
        &self,
        candidate: &PentestCandidateRecord,
        strategy: LivePlanStrategy,
    ) -> Option<LiveTestPlan> {
        let capabilities = self.ctx.capabilities?;
        if matches!(capabilities.target_reachable, EnvCapabilityStatus::Missing) {
            return Some(self.no_plan(
                candidate,
                NoPlanReasonCode::SetupMissing,
                "live verification target is not configured or reachable; set a target URL or launch profile before verifier execution",
            ));
        }
        if matches!(strategy, LivePlanStrategy::DomXss)
            && matches!(capabilities.browser, EnvCapabilityStatus::Missing)
        {
            return Some(self.no_plan(
                candidate,
                NoPlanReasonCode::SetupMissing,
                "browser verification was requested but the Playwright/browser runtime is unavailable",
            ));
        }
        if matches!(
            strategy,
            LivePlanStrategy::FileUploadReviewOnly
                | LivePlanStrategy::BusinessLogicReviewOnly
                | LivePlanStrategy::WebhookTrustReviewOnly
        ) && matches!(capabilities.seed, EnvCapabilityStatus::Missing)
        {
            return Some(self.no_plan(
                candidate,
                NoPlanReasonCode::SetupMissing,
                "this candidate needs seeded disposable fixture state before Nyctos can verify it safely",
            ));
        }
        if matches!(strategy, LivePlanStrategy::IdorObjectIsolation) {
            let has_ready_pair = capabilities.ready_auth_role_pair().is_some()
                || auth_role_pair_capabilities(self.ctx.auth_profiles, &capabilities.auth_roles)
                    .into_iter()
                    .any(|pair| matches!(pair.status, EnvCapabilityStatus::Available));
            if !has_ready_pair {
                let missing = authz_pair_setup_notes(self.ctx.auth_profiles, capabilities);
                return Some(self.no_plan(
                    candidate,
                    NoPlanReasonCode::SetupMissing,
                    format!(
                        "IDOR verification needs a ready owner/accessor auth role pair; setup missing for {}",
                        missing.join("; ")
                    ),
                ));
            }
        }
        None
    }

    pub fn replan_after_failure(
        &self,
        candidate: &PentestCandidateRecord,
        failure_code: Option<&str>,
    ) -> Option<LiveTestPlan> {
        let retryable = matches!(
            failure_code,
            Some("bad_endpoint" | "weak_oracle" | "auth_missing" | "no_executable_plan") | None
        );
        let avoided_urls = if matches!(failure_code, Some("bad_endpoint")) {
            plan_urls_from_raw(&candidate.test_plan)
        } else {
            Vec::new()
        };
        retryable.then(|| self.synthesize_avoiding_urls(candidate, &avoided_urls)).and_then(
            |plan| {
                if matches!(plan, LiveTestPlan::NoPlan(_)) {
                    None
                } else {
                    Some(plan)
                }
            },
        )
    }

    fn trusted_header_auth_bypass(
        &self,
        candidate: &PentestCandidateRecord,
        endpoints: &[EndpointCandidate],
    ) -> LiveTestPlan {
        let Some(endpoint) = endpoint_preferring_admin(endpoints) else {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::RouteNotInferred,
                "trusted-header auth bypass needs an inferred protected/admin endpoint",
            );
        };
        let markers = sensitive_markers(candidate, endpoint);
        let header_name = trusted_header_name(candidate);
        let header_value = trusted_header_value(candidate, self.ctx.auth_profiles)
            .unwrap_or_else(|| "admin@example.com".to_string());
        let baseline = request_for_endpoint(endpoint, "anonymous");
        let mut exploit = request_for_endpoint(endpoint, "anonymous");
        exploit.headers.insert(header_name.clone(), header_value.clone());
        exploit.payload = Some(contextual_payload(
            "trusted-header-auth-bypass",
            PayloadTransport::Header,
            &header_name,
            &header_value,
            "anonymous request receives protected content when trusted identity headers are supplied",
            "normal anonymous request remains forbidden or lacks sensitive markers",
            false,
            "The same anonymous request only becomes sensitive when trusted auth headers are present.",
        ));
        LiveTestPlan::SingleHttp(SingleHttpPlan {
            hypothesis: Some(candidate.hypothesis.clone()),
            request: exploit,
            baseline: Some(baseline),
            benign: None,
            oracle: HttpOracle {
                status_range: Some("2xx".to_string()),
                body_contains: markers,
                ..HttpOracle::default()
            },
            why_this_confirms: Some(
                "Normal anonymous access stays clean, while the same anonymous request with a trusted identity header receives protected content.".to_string(),
            ),
        })
    }

    fn idor(
        &self,
        candidate: &PentestCandidateRecord,
        endpoints: &[EndpointCandidate],
    ) -> LiveTestPlan {
        let Some(endpoint) = endpoints
            .iter()
            .filter(|endpoint| endpoint.is_read_only())
            .find(|endpoint| {
                endpoint.path.contains(':')
                    || endpoint.path.contains('{')
                    || object_id_from_endpoint(endpoint).is_some()
            })
            .or_else(|| endpoints.iter().find(|endpoint| endpoint.is_read_only()))
        else {
            if endpoints.iter().any(|endpoint| endpoint.state_changing) {
                return self.no_plan(
                    candidate,
                    NoPlanReasonCode::StateChangingBlocked,
                    "IDOR/tenant-isolation verification only runs read-only owner-versus-peer checks; inferred endpoints are state-changing",
                );
            }
            return self.no_plan(
                candidate,
                NoPlanReasonCode::RouteNotInferred,
                "IDOR verification needs an inferred read-only object endpoint",
            );
        };
        let broker = AuthRoleBroker::new(self.ctx.auth_profiles);
        let Some((user_a, user_b)) = broker.role_pair("user_a", "user_b") else {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::AuthMissing,
                "IDOR verification needs distinct auth profiles matching owner/accessor semantics",
            );
        };
        let Some((object_endpoint, object)) =
            concrete_authz_object_endpoint(self.ctx.auth_profiles, &user_a, endpoint)
        else {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::MissingSeedData,
                "IDOR route has an object parameter but no configured user A owned object id was discovered",
            );
        };
        let mut markers = sensitive_markers(candidate, &object_endpoint);
        markers.extend(object.positive_markers.clone());
        if let Some(id) = object.id.clone() {
            markers.push(id);
        }
        markers.sort();
        markers.dedup();
        let owner_request = request_for_endpoint(&object_endpoint, &user_a);
        let accessor_request = request_for_endpoint(&object_endpoint, &user_b);
        LiveTestPlan::AuthzObjectOwnership(AuthzObjectOwnershipPlan {
            hypothesis: Some(candidate.hypothesis.clone()),
            object,
            accessor_role: user_b,
            seed_steps: Vec::new(),
            owner_request,
            accessor_request,
            benign_steps: Vec::new(),
            oracle: AuthzOracle::object_ownership(markers),
            why_this_confirms: Some(
                "User A can access the object and user B unexpectedly receives the same sensitive object markers.".to_string(),
            ),
        })
    }

    fn auth_bypass(
        &self,
        candidate: &PentestCandidateRecord,
        endpoints: &[EndpointCandidate],
    ) -> LiveTestPlan {
        let Some(endpoint) = endpoint_preferring_admin(endpoints) else {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::RouteNotInferred,
                "auth bypass verification needs an inferred protected endpoint",
            );
        };
        let broker = AuthRoleBroker::new(self.ctx.auth_profiles);
        let Some(privileged_role) = broker.resolve_role("admin") else {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::AuthMissing,
                "auth bypass verification needs an allowed privileged auth profile for calibration",
            );
        };
        let allowed = request_for_endpoint(endpoint, &privileged_role);
        let anonymous = request_for_endpoint(endpoint, "anonymous");
        LiveTestPlan::DifferentialHttp(DifferentialHttpPlan {
            hypothesis: Some(candidate.hypothesis.clone()),
            steps: vec![allowed.clone(), anonymous],
            benign_steps: vec![allowed],
            oracle: DifferentialOracle {
                oracle_type: "forbidden_equivalence_break".to_string(),
                expected_allowed_step: 0,
                expected_forbidden_step: 1,
                forbidden_status: vec![401, 403, 404],
                sensitive_body_markers: sensitive_markers(candidate, endpoint),
            },
            why_this_confirms: Some(
                "Privileged role receives protected markers, while an anonymous request unexpectedly receives the same protected content.".to_string(),
            ),
        })
    }

    fn csrf(
        &self,
        candidate: &PentestCandidateRecord,
        endpoints: &[EndpointCandidate],
    ) -> LiveTestPlan {
        let Some(endpoint) = endpoints.iter().find(|endpoint| endpoint.state_changing) else {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::RouteNotInferred,
                "CSRF verification needs a concrete state-changing endpoint",
            );
        };
        if !self.ctx.allow_state_changing {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::StateChangingBlocked,
                "CSRF verification is state-changing and requires exploit mode plus state-changing probe opt-in",
            );
        }
        self.no_plan(
            candidate,
            NoPlanReasonCode::MissingSeedData,
            format!(
                "CSRF route {} {} needs seeded form data/reset hooks before Nyctos can safely mutate state",
                endpoint.method, endpoint.path
            ),
        )
    }

    fn dom_xss(
        &self,
        candidate: &PentestCandidateRecord,
        endpoints: &[EndpointCandidate],
    ) -> LiveTestPlan {
        if !self.ctx.browser_checks_enabled {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::BrowserDisabled,
                "DOM/client-side candidate requires browser verification, but browser checks are disabled",
            );
        }
        let base = endpoints
            .first()
            .map(|e| e.url.clone())
            .unwrap_or_else(|| self.ctx.target_urls[0].clone());
        let payload = "<img src=x onerror=alert('nyctos-dom-xss')>";
        let param = candidate_param(candidate).unwrap_or_else(|| "nyctos_probe".to_string());
        let url = append_query(&base, &param, payload);
        LiveTestPlan::BrowserWorkflow(BrowserWorkflowPlan {
            url,
            role: "anonymous".to_string(),
            steps: vec![
                BrowserStep {
                    action: "wait_for_selector".to_string(),
                    url: None,
                    selector: Some("body".to_string()),
                    text: None,
                    value: None,
                    key: None,
                    timeout_ms: Some(5000),
                    ms: None,
                    full_page: None,
                },
                BrowserStep {
                    action: "screenshot".to_string(),
                    url: None,
                    selector: None,
                    text: None,
                    value: None,
                    key: None,
                    timeout_ms: None,
                    ms: None,
                    full_page: Some(true),
                },
            ],
            baseline: Some(Box::new(BrowserWorkflowPlan {
                url: base,
                role: "anonymous".to_string(),
                steps: vec![BrowserStep {
                    action: "wait_for_selector".to_string(),
                    url: None,
                    selector: Some("body".to_string()),
                    text: None,
                    value: None,
                    key: None,
                    timeout_ms: Some(5000),
                    ms: None,
                    full_page: None,
                }],
                baseline: None,
                oracle: BrowserOracle {
                    alert_contains: vec!["nyctos-dom-xss".to_string()],
                    ..BrowserOracle::default()
                },
                payload: None,
                state_changing: false,
                why_this_confirms: None,
            })),
            oracle: BrowserOracle {
                alert_contains: vec!["nyctos-dom-xss".to_string()],
                ..BrowserOracle::default()
            },
            payload: Some(contextual_payload(
                "dom-xss",
                PayloadTransport::Dom,
                &param,
                payload,
                "browser dialog contains nyctos-dom-xss",
                "baseline page does not raise the dialog",
                false,
                "A JavaScript dialog from attacker-controlled input proves the DOM sink executed injected script.",
            )),
            state_changing: false,
            why_this_confirms: Some(
                "Browser executes attacker-controlled DOM payload and captures a DOM-specific alert oracle.".to_string(),
            ),
        })
    }

    fn debug_exposure(
        &self,
        candidate: &PentestCandidateRecord,
        endpoints: &[EndpointCandidate],
    ) -> LiveTestPlan {
        let Some(endpoint) = endpoints.iter().find(|endpoint| endpoint.is_read_only()) else {
            if endpoints.iter().any(|endpoint| endpoint.state_changing) {
                return self.no_plan(
                    candidate,
                    NoPlanReasonCode::StateChangingBlocked,
                    "sensitive exposure verification only runs read-only requests; inferred endpoint is state-changing",
                );
            }
            return self.no_plan(
                candidate,
                NoPlanReasonCode::RouteNotInferred,
                "sensitive exposure verification needs an inferred read-only endpoint",
            );
        };
        let mut request = request_for_endpoint(endpoint, "anonymous");
        request.payload = Some(contextual_payload(
            "debug-exposure",
            PayloadTransport::Query,
            "route",
            &endpoint.path,
            "response contains debug/sensitive marker",
            "target root does not contain the marker",
            false,
            "A sensitive marker from the inferred debug endpoint, absent from baseline, confirms exposure.",
        ));
        LiveTestPlan::SingleHttp(SingleHttpPlan {
            hypothesis: Some(candidate.hypothesis.clone()),
            request,
            baseline: Some(LiveHttpRequest::get(self.ctx.target_urls[0].clone())),
            benign: None,
            oracle: HttpOracle {
                status_range: Some("2xx".to_string()),
                body_contains: sensitive_markers(candidate, endpoint),
                ..HttpOracle::default()
            },
            why_this_confirms: Some(
                "Baseline target is clean and the inferred sensitive route returns vulnerability-specific markers.".to_string(),
            ),
        })
    }

    fn open_redirect(
        &self,
        candidate: &PentestCandidateRecord,
        endpoints: &[EndpointCandidate],
    ) -> LiveTestPlan {
        let Some(endpoint) = endpoints
            .iter()
            .find(|endpoint| endpoint.is_read_only() && endpoint.method != "OPTIONS")
        else {
            if endpoints.iter().any(|endpoint| endpoint.state_changing) {
                return self.no_plan(
                    candidate,
                    NoPlanReasonCode::StateChangingBlocked,
                    "open redirect verification only uses read-only GET/HEAD requests; inferred endpoint is state-changing",
                );
            }
            return self.no_plan(
                candidate,
                NoPlanReasonCode::RouteNotInferred,
                "open redirect verification needs an inferred read-only endpoint",
            );
        };
        let redirect_target = "https://nyctos.invalid/redirect-probe";
        let param = redirect_param(candidate);
        let mut request = request_for_endpoint(endpoint, "anonymous");
        request.url = append_query(&endpoint.url, &param, redirect_target);
        request.payload = Some(contextual_payload(
            "open-redirect",
            PayloadTransport::Query,
            &param,
            redirect_target,
            "Location header points to nyctos.invalid",
            "same endpoint without redirect parameter does not point off-site",
            false,
            "A same-origin request producing an off-site Location header confirms unsafe redirect handling.",
        ));
        LiveTestPlan::SingleHttp(SingleHttpPlan {
            hypothesis: Some(candidate.hypothesis.clone()),
            request,
            baseline: Some(request_for_endpoint(endpoint, "anonymous")),
            benign: None,
            oracle: HttpOracle {
                status_range: Some("3xx".to_string()),
                header_contains: BTreeMap::from([("location".to_string(), "nyctos.invalid".to_string())]),
                ..HttpOracle::default()
            },
            why_this_confirms: Some(
                "Redirect response sends the browser to attacker-controlled host while the baseline route stays clean.".to_string(),
            ),
        })
    }

    fn cors_misconfiguration(
        &self,
        candidate: &PentestCandidateRecord,
        endpoints: &[EndpointCandidate],
    ) -> LiveTestPlan {
        let Some(endpoint) = endpoints.iter().find(|endpoint| endpoint.is_read_only()) else {
            if endpoints.iter().any(|endpoint| endpoint.state_changing) {
                return self.no_plan(
                    candidate,
                    NoPlanReasonCode::StateChangingBlocked,
                    "CORS verification only sends read-only Origin-header probes; inferred endpoint is state-changing",
                );
            }
            return self.no_plan(
                candidate,
                NoPlanReasonCode::RouteNotInferred,
                "CORS verification needs an inferred read-only endpoint",
            );
        };
        let origin = "https://nyctos.invalid";
        let mut request = request_for_endpoint(endpoint, "anonymous");
        request.headers.insert("Origin".to_string(), origin.to_string());
        if request.method == "OPTIONS" {
            request.headers.insert("Access-Control-Request-Method".to_string(), "GET".to_string());
        }
        request.payload = Some(contextual_payload(
            "cors-misconfiguration",
            PayloadTransport::Header,
            "Origin",
            origin,
            "Access-Control-Allow-Origin reflects or allows nyctos.invalid",
            "same endpoint without an Origin header lacks attacker-origin CORS allowance",
            false,
            "A read-only request that allows an untrusted origin provides deterministic CORS evidence.",
        ));
        LiveTestPlan::SingleHttp(SingleHttpPlan {
            hypothesis: Some(candidate.hypothesis.clone()),
            request,
            baseline: Some(request_for_endpoint(endpoint, "anonymous")),
            benign: None,
            oracle: HttpOracle {
                header_contains: BTreeMap::from([(
                    "access-control-allow-origin".to_string(),
                    "nyctos.invalid".to_string(),
                )]),
                ..HttpOracle::default()
            },
            why_this_confirms: Some(
                "The target grants CORS access to an untrusted external origin while the baseline remains clean.".to_string(),
            ),
        })
    }

    fn path_traversal(
        &self,
        candidate: &PentestCandidateRecord,
        endpoints: &[EndpointCandidate],
    ) -> LiveTestPlan {
        let Some(endpoint) = endpoints
            .iter()
            .find(|endpoint| endpoint.method == "GET" && endpoint_has_file_param(endpoint))
        else {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::RouteNotInferred,
                "path traversal verification needs a GET endpoint with a file/path parameter",
            );
        };
        let param = endpoint
            .params
            .iter()
            .find(|p| param_looks_fileish(p))
            .map(String::as_str)
            .unwrap_or("file");
        let mut request = request_for_endpoint(endpoint, "anonymous");
        request.url = append_query(&endpoint.url, param, "../../../../etc/passwd");
        request.payload = Some(contextual_payload(
            "path-traversal",
            PayloadTransport::Query,
            param,
            "../../../../etc/passwd",
            "response contains root:",
            "benign filename does not contain root:",
            false,
            "The traversal payload exposing a known passwd marker, while benign control stays clean, confirms file read traversal.",
        ));
        let mut benign = request_for_endpoint(endpoint, "anonymous");
        benign.url = append_query(&endpoint.url, param, "nyctos-benign.txt");
        LiveTestPlan::SingleHttp(SingleHttpPlan {
            hypothesis: Some(candidate.hypothesis.clone()),
            request,
            baseline: Some(LiveHttpRequest::get(self.ctx.target_urls[0].clone())),
            benign: Some(benign),
            oracle: HttpOracle {
                body_contains: vec!["root:".to_string()],
                ..HttpOracle::default()
            },
            why_this_confirms: Some(
                "Only the traversal payload returns the passwd marker; baseline and benign filename do not.".to_string(),
            ),
        })
    }

    fn stateful_lifecycle_recipe(
        &self,
        candidate: &PentestCandidateRecord,
        endpoints: &[EndpointCandidate],
    ) -> LiveTestPlan {
        let text = candidate_text(candidate);
        let broker = AuthRoleBroker::new(self.ctx.auth_profiles);
        let Some((owner_role, member_role)) = broker.role_pair("owner", "member") else {
            return self.setup_missing(
                candidate,
                "AuthRole",
                "stateful lifecycle recipes need distinct owner/member or inviter/invitee auth roles",
            );
        };
        if let Some(capabilities) = self.ctx.capabilities {
            for role in [&owner_role, &member_role] {
                if !capabilities.auth_role_ready(role) {
                    return self.setup_missing(
                        candidate,
                        "AuthRole",
                        format!("auth role `{role}` is not ready for lifecycle recipe"),
                    );
                }
            }
            if !matches!(capabilities.seed, EnvCapabilityStatus::Available) {
                return self.setup_missing(
                    candidate,
                    "SeedData",
                    "stateful lifecycle recipe needs disposable seeded test data",
                );
            }
            if !self.ctx.allow_state_changing
                || !matches!(capabilities.state_changing, EnvCapabilityStatus::Available)
            {
                return self.no_plan(
                    candidate,
                    NoPlanReasonCode::StateChangingBlocked,
                    "stateful lifecycle recipe mutates fixtures and requires exploit mode plus state-changing probe opt-in",
                );
            }
            if !capabilities.dry_run
                && !matches!(capabilities.reset, EnvCapabilityStatus::Available)
            {
                return self.setup_missing(
                    candidate,
                    "ResetHook",
                    "mutating lifecycle recipe needs a reset hook or explicit cleanup plan",
                );
            }
        } else if !self.ctx.allow_state_changing {
            return self.no_plan(
                candidate,
                NoPlanReasonCode::StateChangingBlocked,
                "stateful lifecycle recipe mutates fixtures and requires state-changing probe opt-in",
            );
        }

        let all = lifecycle_route_endpoints(self.ctx.route_model, self.ctx.target_urls, endpoints);
        let invite_create = all.iter().find(|e| route_looks_invite_create_endpoint(e));
        let invite_accept = all.iter().find(|e| route_looks_invite_accept_endpoint(e));
        let invite_cancel = all.iter().find(|e| route_looks_invite_cancel_endpoint(e));
        let member_add = all.iter().find(|e| route_looks_member_add_endpoint(e));
        let member_remove = all.iter().find(|e| route_looks_member_remove_endpoint(e));
        let member_access =
            all.iter().find(|e| !e.state_changing && route_looks_member_endpoint(e));
        let marker =
            format!("nyctos-lifecycle-{}", candidate.id.chars().take(8).collect::<String>());

        if text.contains("direct member")
            || text.contains("without invite")
            || text.contains("without consent")
        {
            let Some(add) = member_add else {
                return self.setup_missing(
                    candidate,
                    "SeedData",
                    "direct member-add recipe needs a member creation route",
                );
            };
            let Some(access) = member_access else {
                return self.setup_missing(candidate, "SeedData", "direct member-add recipe needs a read-only member access route for postcondition");
            };
            return LiveTestPlan::HttpWorkflow(HttpWorkflowPlan {
                hypothesis: Some(candidate.hypothesis.clone()),
                steps: vec![
                    lifecycle_step(access, &member_role, HttpWorkflowStepPurpose::PositiveControl, "member initially lacks access", None, Some(status_oracle(vec![401, 403, 404]))),
                    lifecycle_step(add, &owner_role, HttpWorkflowStepPurpose::Exploit, "owner directly adds member without invite/consent", Some(member_json(&member_role, &marker)), Some(status_oracle(vec![200, 201, 204]))),
                    lifecycle_step(access, &member_role, HttpWorkflowStepPurpose::Postcondition, "member gains access after direct add", None, Some(HttpOracle { status_range: Some("2xx".to_string()), body_contains: vec![marker.clone()], ..HttpOracle::default() })),
                ],
                benign_steps: Vec::new(),
                cleanup_steps: member_remove.map(|remove| vec![lifecycle_step(remove, &owner_role, HttpWorkflowStepPurpose::Cleanup, "remove directly added member", Some(member_json(&member_role, &marker)), Some(status_oracle(vec![200, 202, 204, 404])))]).unwrap_or_default(),
                oracle: HttpOracle { status_range: Some("2xx".to_string()), body_contains: vec![marker.clone()], ..HttpOracle::default() },
                oracle_step: Some(2),
                why_this_confirms: Some("The member cannot access the fixture before the direct add, the add succeeds without an invite/consent step, and the member then sees the controlled marker.".to_string()),
                recipe: Some(recipe_metadata("direct_member_add_without_invite_consent", &owner_role, &member_role, member_remove.is_none())),
            });
        }

        let (Some(create), Some(accept)) = (invite_create, invite_accept) else {
            return self.setup_missing(
                candidate,
                "SeedData",
                "invite lifecycle recipe needs invite creation and acceptance routes that expose a token/id",
            );
        };
        if text.contains("finalized") || text.contains("token acceptance") {
            return LiveTestPlan::HttpWorkflow(HttpWorkflowPlan {
                hypothesis: Some(candidate.hypothesis.clone()),
                steps: vec![
                    invite_seed_step(create, &owner_role, &member_role, &marker),
                    lifecycle_step(accept, &member_role, HttpWorkflowStepPurpose::PositiveControl, "invite token accepts once", Some(token_json("invite_token", &marker)), Some(HttpOracle { status_range: Some("2xx".to_string()), body_contains: vec![marker.clone()], ..HttpOracle::default() })),
                    lifecycle_step(accept, &member_role, HttpWorkflowStepPurpose::Exploit, "finalized invite token accepts again", Some(token_json("invite_token", &marker)), Some(HttpOracle { status_range: Some("2xx".to_string()), body_contains: vec![marker.clone()], ..HttpOracle::default() })),
                ],
                benign_steps: Vec::new(),
                cleanup_steps: Vec::new(),
                oracle: HttpOracle { status_range: Some("2xx".to_string()), body_contains: vec![marker.clone()], ..HttpOracle::default() },
                oracle_step: Some(2),
                why_this_confirms: Some("The recipe captures a real invite token, finalizes it once, then proves the finalized token is still accepted.".to_string()),
                recipe: Some(recipe_metadata("finalized_explorer_invite_token_acceptance", &owner_role, &member_role, true)),
            });
        }

        let Some(cancel) = invite_cancel else {
            return self.setup_missing(
                candidate,
                "SeedData",
                "stale inviter cancel recipe needs an invite cancel/delete route",
            );
        };
        let mut stale_steps = vec![
            invite_seed_step(create, &owner_role, &member_role, &marker),
            lifecycle_step(
                accept,
                &member_role,
                HttpWorkflowStepPurpose::StateTransition,
                "invitee accepts invite and finalizes membership",
                Some(token_json("invite_token", &marker)),
                Some(HttpOracle {
                    status_range: Some("2xx".to_string()),
                    body_contains: vec![marker.clone()],
                    ..HttpOracle::default()
                }),
            ),
        ];
        if let (Some(remove), Some(access)) = (member_remove, member_access) {
            stale_steps.push(lifecycle_step(
                remove,
                &owner_role,
                HttpWorkflowStepPurpose::StateTransition,
                "remove member after invite finalization",
                Some(member_json(&member_role, &marker)),
                Some(status_oracle(vec![200, 202, 204])),
            ));
            stale_steps.push(lifecycle_step(
                access,
                &member_role,
                HttpWorkflowStepPurpose::Postcondition,
                "member has no access after removal",
                None,
                Some(status_oracle(vec![401, 403, 404])),
            ));
        }
        stale_steps.push(lifecycle_step(
            cancel,
            &owner_role,
            HttpWorkflowStepPurpose::Exploit,
            "stale inviter cancel succeeds after finalization",
            Some(token_json("invite_token", &marker)),
            Some(status_oracle(vec![200, 202, 204])),
        ));
        LiveTestPlan::HttpWorkflow(HttpWorkflowPlan {
            hypothesis: Some(candidate.hypothesis.clone()),
            steps: stale_steps,
            benign_steps: Vec::new(),
            cleanup_steps: Vec::new(),
            oracle: HttpOracle { status_range: Some("2xx".to_string()), body_contains: vec![marker.clone()], ..HttpOracle::default() },
            oracle_step: Some(1),
            why_this_confirms: Some("The recipe creates and finalizes an invite, then verifies the stale inviter can still cancel it after lifecycle state changed.".to_string()),
            recipe: Some(recipe_metadata(if text.contains("explorer") { "explorer_invite_stale_inviter_cancel" } else { "trip_invite_stale_inviter_cancel" }, &owner_role, &member_role, true)),
        })
    }

    fn setup_missing(
        &self,
        candidate: &PentestCandidateRecord,
        kind: &str,
        message: impl Into<String>,
    ) -> LiveTestPlan {
        match self.no_plan(candidate, NoPlanReasonCode::SetupMissing, message) {
            LiveTestPlan::NoPlan(mut plan) => {
                plan.no_plan_reason =
                    plan.no_plan_reason.with_context("setup_missing", kind.to_string());
                LiveTestPlan::NoPlan(plan)
            }
            plan => plan,
        }
    }

    fn no_plan(
        &self,
        candidate: &PentestCandidateRecord,
        code: NoPlanReasonCode,
        message: impl Into<String>,
    ) -> LiveTestPlan {
        let mut reason = NoPlanReason::new(code, message)
            .with_context("candidate_id", &candidate.id)
            .with_context("vuln_class", &candidate.vuln_class)
            .with_context("source", &candidate.source);
        if let Some(path) = candidate_source_path(candidate) {
            reason = reason.with_context("source_path", path);
        }
        if let Some(capabilities) = self.ctx.capabilities {
            reason = reason
                .with_context("target_reachable", format!("{:?}", capabilities.target_reachable))
                .with_context("browser", format!("{:?}", capabilities.browser))
                .with_context("seed", format!("{:?}", capabilities.seed))
                .with_context("reset", format!("{:?}", capabilities.reset))
                .with_context("state_changing", format!("{:?}", capabilities.state_changing));
            let missing_auth = capabilities
                .auth_roles
                .iter()
                .filter(|role| !role.ready())
                .map(|role| role.role.clone())
                .collect::<Vec<_>>();
            if !missing_auth.is_empty() {
                reason = reason.with_context("missing_auth_roles", missing_auth.join(","));
            }
        }
        LiveTestPlan::no_plan(reason)
    }
}

fn plan_urls_from_raw(raw: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_plan_urls(&value, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_plan_urls(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(obj) => {
            if let Some(url) = obj.get("url").and_then(|v| v.as_str()) {
                out.push(url.to_string());
            }
            for key in [
                "request",
                "baseline",
                "benign",
                "benign_control",
                "owner_request",
                "accessor_request",
            ] {
                if let Some(child) = obj.get(key) {
                    collect_plan_urls(child, out);
                }
            }
            for key in ["steps", "benign_steps", "setup_steps", "seed_steps"] {
                if let Some(items) = obj.get(key).and_then(|v| v.as_array()) {
                    for item in items {
                        collect_plan_urls(item, out);
                    }
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_plan_urls(item, out);
            }
        }
        _ => {}
    }
}

fn auth_role_capability(
    profile: &ProjectAuthProfile,
    env_overrides: &BTreeMap<String, String>,
    browser: &EnvCapabilityStatus,
) -> AuthRoleCapability {
    let mut missing_env_vars = Vec::new();
    for var in required_env_vars(profile) {
        if env_overrides.get(&var).is_none_or(|v| v.is_empty()) && std::env::var(&var).is_err() {
            missing_env_vars.push(var);
        }
    }
    let mut missing_artifacts = Vec::new();
    if matches!(profile.mode, ProjectAuthMode::SessionImport) {
        match profile.session_import_path.as_deref().filter(|p| !p.trim().is_empty()) {
            Some(path) if std::path::Path::new(path).exists() => {}
            Some(path) => missing_artifacts.push(path.to_string()),
            None => missing_artifacts.push("session_import_path".to_string()),
        }
    }
    let mut notes = Vec::new();
    if !missing_env_vars.is_empty() {
        notes.push(format!("missing env vars: {}", missing_env_vars.join(",")));
    }
    if !missing_artifacts.is_empty() {
        notes.push(format!("missing auth artifacts: {}", missing_artifacts.join(",")));
    }
    if matches!(profile.mode, ProjectAuthMode::HeaderInjection)
        && profile.bearer_token_env.is_none()
        && profile.cookie_env.is_none()
        && profile.headers.is_empty()
    {
        notes.push("missing role capability: header injection needs bearer_token_env, cookie_env, or headers".to_string());
    }
    if matches!(profile.mode, ProjectAuthMode::AiAuto) {
        if profile.username.as_deref().is_none_or(|value| value.trim().is_empty())
            && profile.username_env.is_none()
            && profile.login_email_env.is_none()
        {
            notes.push(
                "missing role capability: AI auto needs username_env, login_email_env, or username"
                    .to_string(),
            );
        }
        if profile.password_env.is_none() {
            notes.push("missing role capability: AI auto needs password_env".to_string());
        }
    }
    if matches!(
        profile.mode,
        ProjectAuthMode::BrowserLogin
            | ProjectAuthMode::ManualSso
            | ProjectAuthMode::OtpEmailManual
            | ProjectAuthMode::OtpEmailMailbox
            | ProjectAuthMode::AiAuto
            | ProjectAuthMode::OidcDevice
    ) && !matches!(browser, EnvCapabilityStatus::Available)
    {
        notes.push("browser runtime unavailable for browser-backed auth".to_string());
    }
    if matches!(profile.mode, ProjectAuthMode::OtpEmailMailbox)
        && profile.otp_source.as_ref().and_then(|otp| otp.mailbox_url.as_ref()).is_none()
    {
        notes.push("mailbox OTP source missing mailbox_url".to_string());
    }
    if matches!(profile.mode, ProjectAuthMode::OtpEmailManual) {
        notes.push(
            "auth unsupported: manual email OTP entry is configured but not wired".to_string(),
        );
    }
    if matches!(profile.mode, ProjectAuthMode::OtpEmailMailbox)
        && profile.otp_source.as_ref().and_then(|otp| otp.mailbox_url.as_ref()).is_some()
    {
        notes.push(
            "auth unsupported: mailbox OTP login capture is configured but not wired".to_string(),
        );
    }
    let status = if notes.is_empty() {
        EnvCapabilityStatus::Available
    } else {
        EnvCapabilityStatus::Missing
    };
    AuthRoleCapability {
        role: profile.role.clone(),
        mode: format!("{:?}", profile.mode).to_ascii_snake_case(),
        status,
        missing_env_vars,
        missing_artifacts,
        notes,
    }
}

fn auth_role_pair_capabilities(
    profiles: &[ProjectAuthProfile],
    auth_roles: &[AuthRoleCapability],
) -> Vec<AuthRolePairCapability> {
    let broker = AuthRoleBroker::new(profiles);
    broker
        .usable_role_pairs()
        .into_iter()
        .map(|(owner_role, accessor_role)| {
            let owner_ready = role_ready(auth_roles, &owner_role);
            let accessor_ready = role_ready(auth_roles, &accessor_role);
            let owns_object = profiles
                .iter()
                .find(|profile| profile.role == owner_role)
                .is_some_and(|profile| !profile.owned_objects.is_empty());
            let mut notes = Vec::new();
            if !owner_ready {
                notes.push(format!("owner role `{owner_role}` is not ready"));
            }
            if !accessor_ready {
                notes.push(format!("accessor role `{accessor_role}` is not ready"));
            }
            if !owns_object {
                notes.push(format!("owner role `{owner_role}` has no configured owned object"));
            }
            AuthRolePairCapability {
                owner_role,
                accessor_role,
                status: if notes.is_empty() {
                    EnvCapabilityStatus::Available
                } else {
                    EnvCapabilityStatus::Missing
                },
                notes,
            }
        })
        .collect()
}

fn role_ready(auth_roles: &[AuthRoleCapability], role: &str) -> bool {
    role == "anonymous" || auth_roles.iter().any(|cap| cap.role == role && cap.ready())
}

fn authz_pair_setup_notes(
    profiles: &[ProjectAuthProfile],
    capabilities: &EnvCapabilityReport,
) -> Vec<String> {
    let pairs = auth_role_pair_capabilities(profiles, &capabilities.auth_roles);
    if pairs.is_empty() {
        return vec!["no distinct roles match owner/accessor semantics".to_string()];
    }
    pairs
        .into_iter()
        .filter(|pair| !matches!(pair.status, EnvCapabilityStatus::Available))
        .flat_map(|pair| {
            let mut notes = pair.notes;
            for role in [&pair.owner_role, &pair.accessor_role] {
                if let Some(cap) = capabilities.auth_role(role) {
                    if !cap.missing_env_vars.is_empty() {
                        notes.push(format!(
                            "{} missing env {}",
                            cap.role,
                            cap.missing_env_vars.join(",")
                        ));
                    }
                    for note in &cap.notes {
                        if !notes.contains(note) {
                            notes.push(format!("{}: {note}", cap.role));
                        }
                    }
                }
            }
            notes
        })
        .collect::<Vec<_>>()
}

fn required_env_vars(profile: &ProjectAuthProfile) -> Vec<String> {
    let mut vars = Vec::new();
    for value in [
        profile.username_env.as_ref(),
        profile.login_email_env.as_ref(),
        profile.password_env.as_ref(),
        profile.cookie_env.as_ref(),
        profile.bearer_token_env.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        vars.push(value.clone());
    }
    vars.extend(profile.headers.iter().filter_map(|header| header.value_env.clone()));
    if let Some(otp) = &profile.otp_source {
        vars.extend(
            [
                otp.email_env.clone(),
                otp.imap_url_env.clone(),
                otp.imap_username_env.clone(),
                otp.imap_password_env.clone(),
            ]
            .into_iter()
            .flatten(),
        );
    }
    vars.sort();
    vars.dedup();
    vars
}

trait AsciiSnakeCase {
    fn to_ascii_snake_case(&self) -> String;
}

impl AsciiSnakeCase for str {
    fn to_ascii_snake_case(&self) -> String {
        let mut out = String::new();
        for (idx, ch) in self.chars().enumerate() {
            if ch.is_ascii_uppercase() {
                if idx > 0 {
                    out.push('_');
                }
                out.push(ch.to_ascii_lowercase());
            } else {
                out.push(ch);
            }
        }
        out
    }
}

fn classify_strategy(candidate: &PentestCandidateRecord) -> LivePlanStrategy {
    let text = candidate_text(candidate);
    let class = candidate.vuln_class.trim().to_ascii_uppercase().replace('-', "_");
    match class.as_str() {
        "AUTH_BYPASS" | "AUTHENTICATION_BYPASS" => {
            if contains_any(&text, &["dev mail", "dev_mail", "/api/dev/mail", "otp"]) {
                return LivePlanStrategy::DebugExposure;
            }
            if contains_any(
                &text,
                &[
                    "trusted header",
                    "x-forwarded-user",
                    "x-original-user",
                    "header auth",
                    "cf-access-authenticated-user-email",
                    "cf-access",
                ],
            ) {
                return LivePlanStrategy::TrustedHeaderAuthBypass;
            }
            return LivePlanStrategy::AuthBypassProtectedEndpoint;
        }
        "IDOR"
        | "IDOR_CANDIDATE"
        | "ACCESS_CONTROL"
        | "BROKEN_ACCESS_CONTROL"
        | "TENANT_ISOLATION"
        | "TENANT_ACCOUNT_ISOLATION"
        | "OBJECT_OWNERSHIP" => {
            return LivePlanStrategy::IdorObjectIsolation;
        }
        "DOM_XSS" | "XSS" | "CLIENT_SIDE_XSS" | "CLIENT_SIDE_INJECTION" => {
            return LivePlanStrategy::DomXss;
        }
        "OPEN_REDIRECT" | "UNSAFE_REDIRECT" | "UNVALIDATED_REDIRECT" => {
            return LivePlanStrategy::OpenRedirect;
        }
        "SSRF" | "SERVER_SIDE_REQUEST_FORGERY" => return LivePlanStrategy::SsrfUrlFetch,
        "DEBUG_EXPOSURE"
        | "DIAGNOSTIC_EXPOSURE"
        | "CONFIG_EXPOSURE"
        | "ADMIN_DEBUG_EXPOSURE"
        | "ADMIN_SURFACE" => {
            return LivePlanStrategy::DebugExposure;
        }
        "CORS_MISCONFIG" | "CORS_MISCONFIGURATION" => {
            return LivePlanStrategy::CorsMisconfiguration;
        }
        "WEBHOOK_TRUST" | "WEBHOOK_TRUST_BOUNDARY" | "WEBHOOK_CALLBACK_TRUST" => {
            return LivePlanStrategy::WebhookTrustReviewOnly;
        }
        "FILE_UPLOAD_FLOW" | "UNSAFE_FILE_UPLOAD" => {
            return LivePlanStrategy::FileUploadReviewOnly;
        }
        "FILE_DOWNLOAD_FLOW" | "UNSAFE_FILE_DOWNLOAD" => {
            return LivePlanStrategy::PathTraversal;
        }
        "BUSINESS_LOGIC_ABUSE"
            if contains_any(
                &text,
                &[
                    "stale inviter",
                    "finalized invite",
                    "invite token acceptance",
                    "direct member add",
                    "without invite",
                    "without consent",
                    "member lifecycle",
                    "invite lifecycle",
                ],
            ) =>
        {
            return LivePlanStrategy::StatefulLifecycleRecipe;
        }
        "BUSINESS_LOGIC_ABUSE" | "PAYMENT_LOGIC_ABUSE" | "CREDITS_ABUSE" => {
            return LivePlanStrategy::BusinessLogicReviewOnly;
        }
        _ => {}
    }
    if contains_any(&text, &["dependency", "cve-", "ghsa-", "osv", "trivy", "package", "iac"]) {
        return LivePlanStrategy::DependencyReviewOnly;
    }
    if contains_any(
        &text,
        &[
            "trusted header",
            "x-forwarded-user",
            "x-original-user",
            "header auth",
            "cf-access-authenticated-user-email",
            "cf-access",
        ],
    ) {
        return LivePlanStrategy::TrustedHeaderAuthBypass;
    }
    if contains_any(
        &text,
        &["idor", "object isolation", "tenant isolation", "tenant", "user b", "user a"],
    ) {
        return LivePlanStrategy::IdorObjectIsolation;
    }
    if contains_any(
        &text,
        &[
            "stale inviter",
            "finalized invite",
            "invite token acceptance",
            "direct member add",
            "without invite",
            "without consent",
            "member lifecycle",
            "invite lifecycle",
        ],
    ) {
        return LivePlanStrategy::StatefulLifecycleRecipe;
    }
    if contains_any(&text, &["csrf", "cross-site request"]) {
        return LivePlanStrategy::Csrf;
    }
    if contains_any(&text, &["dom xss", "client-side", "innerhtml", "insertadjacenthtml", "xss"]) {
        return LivePlanStrategy::DomXss;
    }
    if contains_any(&text, &["open redirect", "unsafe redirect", "url scheme", "javascript:"]) {
        return LivePlanStrategy::OpenRedirect;
    }
    if contains_any(&text, &["cors", "access-control-allow-origin", "origin header"]) {
        return LivePlanStrategy::CorsMisconfiguration;
    }
    if contains_any(&text, &["path traversal", "../", "file read", "directory traversal"]) {
        return LivePlanStrategy::PathTraversal;
    }
    if contains_any(&text, &["file upload", "upload/import", "state-changing upload"]) {
        return LivePlanStrategy::FileUploadReviewOnly;
    }
    if contains_any(&text, &["file download", "download/export"]) {
        return LivePlanStrategy::PathTraversal;
    }
    if contains_any(&text, &["webhook", "callback trust", "signature bypass", "event replay"]) {
        return LivePlanStrategy::WebhookTrustReviewOnly;
    }
    if contains_any(&text, &["ssrf", "url fetch", "server-side request"]) {
        return LivePlanStrategy::SsrfUrlFetch;
    }
    if contains_any(&text, &["payment", "credit", "coupon", "price", "billing"]) {
        return LivePlanStrategy::BusinessLogicReviewOnly;
    }
    if contains_any(&text, &["command injection", "shell injection", "exec("]) {
        return LivePlanStrategy::CommandInjection;
    }
    if contains_any(&text, &["sql injection", "sqli", "select ", "where "]) {
        return LivePlanStrategy::SqlInjection;
    }
    if contains_any(
        &text,
        &["debug", "dev mail", "dev_mail", "admin", "swagger", "openapi", "sensitive", "exposure"],
    ) {
        return LivePlanStrategy::DebugExposure;
    }
    LivePlanStrategy::GenericReviewOnly
}

fn infer_endpoints(
    candidate: &PentestCandidateRecord,
    route_model: Option<&RouteModel>,
    target_urls: &[String],
) -> Vec<EndpointCandidate> {
    let mut out = Vec::new();
    for endpoint in endpoints_from_components(candidate, target_urls) {
        push_endpoint(&mut out, endpoint);
    }
    if let Some(model) = route_model {
        for endpoint in endpoints_from_route_model(candidate, model, target_urls) {
            push_endpoint(&mut out, endpoint);
        }
        for endpoint in endpoints_from_api_clients(candidate, model, target_urls) {
            push_endpoint(&mut out, endpoint);
        }
    }
    for endpoint in endpoints_from_text(candidate, target_urls) {
        push_endpoint(&mut out, endpoint);
    }
    for endpoint in endpoints_from_source_path(candidate, target_urls) {
        push_endpoint(&mut out, endpoint);
    }
    out.sort_by(|a, b| endpoint_rank(a).cmp(&endpoint_rank(b)));
    out
}

fn endpoints_from_components(
    candidate: &PentestCandidateRecord,
    target_urls: &[String],
) -> Vec<EndpointCandidate> {
    let mut out = Vec::new();
    for component in &candidate.affected_components {
        let Some(obj) = component.as_object() else {
            continue;
        };
        let method =
            obj.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_ascii_uppercase();
        let params = component_params(obj);
        let body_fields = component_string_array(obj, "body_fields");
        let state_changing = obj
            .get("state_changing")
            .or_else(|| obj.get("destructive"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        for key in ["url", "matched_at", "uri", "endpoint", "url_path", "route", "action"] {
            if let Some(raw) = obj.get(key).and_then(|v| v.as_str()) {
                if let Some(endpoint) = endpoint_from_raw(
                    &method,
                    raw,
                    state_changing,
                    params.clone(),
                    body_fields.clone(),
                    key,
                    target_urls,
                ) {
                    out.push(endpoint);
                }
            }
        }
    }
    out
}

fn endpoints_from_route_model(
    candidate: &PentestCandidateRecord,
    model: &RouteModel,
    target_urls: &[String],
) -> Vec<EndpointCandidate> {
    let source_path = candidate_source_path(candidate);
    let mut out = Vec::new();
    for route in &model.backend_routes {
        let matched_source = source_path.as_deref().is_some_and(|path| {
            route.handler_file.as_deref() == Some(path)
                || route.evidence.iter().any(|e| e.path == path)
        });
        let matched_text = candidate_text(candidate).contains(&route.path.to_ascii_lowercase());
        if matched_source || matched_text {
            out.push(endpoint_from_route(route, target_urls));
        }
    }
    out
}

fn endpoints_from_api_clients(
    candidate: &PentestCandidateRecord,
    model: &RouteModel,
    target_urls: &[String],
) -> Vec<EndpointCandidate> {
    let source_path = candidate_source_path(candidate);
    let mut out = Vec::new();
    for call in &model.api_client_calls {
        let matched_source = source_path.as_deref().is_some_and(|path| {
            call.file.as_deref() == Some(path) || call.evidence.iter().any(|e| e.path == path)
        });
        let matched_text = candidate_text(candidate).contains(&call.path.to_ascii_lowercase());
        if matched_source || matched_text {
            out.push(endpoint_from_api_call(call, target_urls));
        }
    }
    out
}

fn endpoints_from_text(
    candidate: &PentestCandidateRecord,
    target_urls: &[String],
) -> Vec<EndpointCandidate> {
    let re = Regex::new(r#"(?P<path>/(?:api|admin|debug|dev|mail|account|accounts|user|users|tenant|tenants|config|settings|auth|oauth|callback|proxy|fetch|webhook|trip|search|redirect|login)[A-Za-z0-9_./:{}-]*)"#)
        .expect("path inference regex");
    let mut out = Vec::new();
    for captures in re.captures_iter(&format!("{} {}", candidate.title, candidate.hypothesis)) {
        if let Some(path) = captures.name("path").map(|m| m.as_str()) {
            if let Some(endpoint) = endpoint_from_raw(
                "GET",
                path,
                false,
                Vec::new(),
                Vec::new(),
                "candidate_text",
                target_urls,
            ) {
                out.push(endpoint);
            }
        }
    }
    out
}

fn endpoints_from_source_path(
    candidate: &PentestCandidateRecord,
    target_urls: &[String],
) -> Vec<EndpointCandidate> {
    let Some(path) = candidate_source_path(candidate) else {
        return Vec::new();
    };
    let file = path.rsplit('/').next().unwrap_or(&path);
    let stem = file.split('.').next().unwrap_or(file).replace('_', "-");
    if stem.is_empty() || matches!(stem.as_str(), "mod" | "index" | "main" | "lib") {
        return Vec::new();
    }
    let mut paths = Vec::new();
    if stem.contains("dev-mail") {
        paths.push("/dev/mail".to_string());
        paths.push("/api/dev/mail".to_string());
    } else if stem.contains("admin") {
        paths.push("/admin".to_string());
        paths.push("/api/admin".to_string());
    } else if path.contains("handler") || path.contains("route") || path.contains("controller") {
        paths.push(format!("/api/{stem}"));
        paths.push(format!("/{stem}"));
    }
    paths
        .into_iter()
        .filter_map(|path| {
            endpoint_from_raw(
                "GET",
                &path,
                false,
                Vec::new(),
                Vec::new(),
                "source_path",
                target_urls,
            )
        })
        .collect()
}

fn endpoint_from_route(route: &RouteModelEndpoint, target_urls: &[String]) -> EndpointCandidate {
    let url = absolute_url(&route.path, target_urls).unwrap_or_else(|| route.path.clone());
    EndpointCandidate {
        method: route.method.to_ascii_uppercase(),
        path: route.path.clone(),
        url,
        state_changing: route.state_changing,
        params: route.params.clone(),
        body_fields: route.body_fields.clone(),
        source: route.handler_file.clone().unwrap_or_else(|| "route_model".to_string()),
    }
}

fn endpoint_from_api_call(call: &ApiClientCallModel, target_urls: &[String]) -> EndpointCandidate {
    let url = absolute_url(&call.path, target_urls).unwrap_or_else(|| call.path.clone());
    EndpointCandidate {
        method: call.method.to_ascii_uppercase(),
        path: call.path.clone(),
        url,
        state_changing: !matches!(call.method.as_str(), "GET" | "HEAD" | "OPTIONS"),
        params: route_params(&call.path),
        body_fields: Vec::new(),
        source: call.file.clone().unwrap_or_else(|| "api_client".to_string()),
    }
}

fn endpoint_from_raw(
    method: &str,
    raw: &str,
    state_changing: bool,
    params: Vec<String>,
    body_fields: Vec<String>,
    source: &str,
    target_urls: &[String],
) -> Option<EndpointCandidate> {
    if looks_like_local_filesystem_path(raw) || looks_like_source_location_path(raw) {
        return None;
    }
    let url = absolute_url(raw, target_urls)?;
    if !target_urls.iter().any(|target| pentest_tools::url_is_under_target(&url, target)) {
        return None;
    }
    let path =
        reqwest::Url::parse(&url).map(|u| u.path().to_string()).unwrap_or_else(|_| raw.to_string());
    Some(EndpointCandidate {
        method: method.to_ascii_uppercase(),
        path,
        url,
        state_changing,
        params,
        body_fields,
        source: source.to_string(),
    })
}

fn absolute_url(raw: &str, target_urls: &[String]) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return Some(raw.to_string());
    }
    let base = target_urls.first()?.trim_end_matches('/');
    if raw.starts_with('/') {
        let mut parsed = reqwest::Url::parse(base).ok()?;
        parsed.set_path("");
        parsed.set_query(None);
        parsed.set_fragment(None);
        Some(format!("{}{}", parsed.as_str().trim_end_matches('/'), raw))
    } else {
        Some(format!("{base}/{raw}"))
    }
}

fn looks_like_local_filesystem_path(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    (lower.starts_with("/users/") || lower.starts_with("/home/"))
        && contains_any(&lower, &["/library/", "/application", "/src/", "/workspace/"])
}

fn looks_like_source_location_path(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    [".rs:", ".js:", ".ts:", ".tsx:", ".jsx:", ".py:", ".go:", ".rb:", ".php:"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn request_for_endpoint(endpoint: &EndpointCandidate, role: &str) -> LiveHttpRequest {
    LiveHttpRequest {
        method: endpoint.method.clone(),
        url: endpoint.url.clone(),
        path: Some(endpoint.path.clone()),
        headers: BTreeMap::new(),
        body: None,
        json: None,
        captures: None,
        role: role.to_string(),
        destructive: endpoint.state_changing,
        payload: None,
        label: Some(endpoint.source.clone()),
        purpose: None,
        oracle: None,
    }
}

fn lifecycle_route_endpoints(
    model: Option<&RouteModel>,
    target_urls: &[String],
    matched: &[EndpointCandidate],
) -> Vec<EndpointCandidate> {
    let mut out = matched.to_vec();
    if let Some(model) = model {
        out.extend(
            model.backend_routes.iter().map(|route| endpoint_from_route(route, target_urls)),
        );
    }
    out.sort_by(|a, b| a.url.cmp(&b.url).then(a.method.cmp(&b.method)));
    out.dedup_by(|a, b| a.url == b.url && a.method == b.method);
    out
}

fn lifecycle_step(
    endpoint: &EndpointCandidate,
    role: &str,
    purpose: HttpWorkflowStepPurpose,
    label: &str,
    json: Option<serde_json::Value>,
    oracle: Option<HttpOracle>,
) -> LiveHttpRequest {
    let mut request = request_for_endpoint(endpoint, role);
    request.url = template_token_url(&request.url, endpoint);
    request.json = json;
    request.purpose = Some(purpose);
    request.label = Some(label.to_string());
    request.oracle = oracle;
    request.destructive =
        request.destructive || purpose != HttpWorkflowStepPurpose::PositiveControl;
    request
}

fn invite_seed_step(
    endpoint: &EndpointCandidate,
    inviter_role: &str,
    invitee_role: &str,
    marker: &str,
) -> LiveHttpRequest {
    let mut request = lifecycle_step(
        endpoint,
        inviter_role,
        HttpWorkflowStepPurpose::Seed,
        "create disposable invite and capture token",
        Some(member_json(invitee_role, marker)),
        Some(HttpOracle { status_range: Some("2xx".to_string()), ..HttpOracle::default() }),
    );
    request.captures = Some(serde_json::json!({
        "invite_token": {
            "from": "json",
            "path": "token",
            "regex": r#"([A-Za-z0-9_.:-]+)"#
        },
        "invite_token_fallback": {
            "from": "regex_body",
            "regex": r#"(?i)"(?:token|invite_token|invitation_token|code|id|invite_id)"\s*:\s*"?([A-Za-z0-9_.:-]+)"?"#
        }
    }));
    request
}

fn recipe_metadata(
    id: &str,
    owner_role: &str,
    member_role: &str,
    reset_required: bool,
) -> StatefulFixtureRecipe {
    StatefulFixtureRecipe {
        id: id.to_string(),
        fixture: Some("lifecycle_invite_member".to_string()),
        reset_required: Some(reset_required),
        cleanup_required: Some(!reset_required),
        required_roles: vec![owner_role.to_string(), member_role.to_string()],
    }
}

fn status_oracle(expect_status: Vec<u16>) -> HttpOracle {
    HttpOracle { expect_status, ..HttpOracle::default() }
}

fn token_json(token_var: &str, marker: &str) -> serde_json::Value {
    serde_json::json!({
        "token": format!("{{{{{token_var}}}}}"),
        "invite_token": format!("{{{{{token_var}}}}}"),
        "marker": marker,
    })
}

fn member_json(member_role: &str, marker: &str) -> serde_json::Value {
    serde_json::json!({
        "email": format!("{member_role}@nyctos.test"),
        "user": member_role,
        "member": member_role,
        "role": "member",
        "marker": marker,
    })
}

fn template_token_url(url: &str, endpoint: &EndpointCandidate) -> String {
    let mut out = url.to_string();
    for param in &endpoint.params {
        if param.to_ascii_lowercase().contains("token")
            || param.to_ascii_lowercase().contains("code")
            || param.to_ascii_lowercase().contains("invite")
            || param == "id"
        {
            out = out
                .replace(&format!(":{param}"), "{{invite_token}}")
                .replace(&format!("{{{param}}}"), "{{invite_token}}");
        }
    }
    out
}

fn route_looks_invite_create_endpoint(endpoint: &EndpointCandidate) -> bool {
    let path = endpoint.path.to_ascii_lowercase();
    endpoint.state_changing
        && path.contains("invite")
        && !["accept", "join", "redeem", "consume", "cancel", "delete"]
            .iter()
            .any(|needle| path.contains(needle))
}

fn route_looks_invite_accept_endpoint(endpoint: &EndpointCandidate) -> bool {
    let path = endpoint.path.to_ascii_lowercase();
    endpoint.state_changing
        && path.contains("invite")
        && ["accept", "join", "redeem", "consume"].iter().any(|needle| path.contains(needle))
}

fn route_looks_invite_cancel_endpoint(endpoint: &EndpointCandidate) -> bool {
    let path = endpoint.path.to_ascii_lowercase();
    endpoint.state_changing
        && path.contains("invite")
        && (matches!(endpoint.method.as_str(), "DELETE")
            || ["cancel", "delete", "revoke"].iter().any(|needle| path.contains(needle)))
}

fn route_looks_member_endpoint(endpoint: &EndpointCandidate) -> bool {
    let path = endpoint.path.to_ascii_lowercase();
    path.contains("member") || path.contains("participant") || path.contains("explorer")
}

fn route_looks_member_add_endpoint(endpoint: &EndpointCandidate) -> bool {
    endpoint.state_changing
        && route_looks_member_endpoint(endpoint)
        && !route_looks_member_remove_endpoint(endpoint)
}

fn route_looks_member_remove_endpoint(endpoint: &EndpointCandidate) -> bool {
    let path = endpoint.path.to_ascii_lowercase();
    endpoint.state_changing
        && route_looks_member_endpoint(endpoint)
        && (matches!(endpoint.method.as_str(), "DELETE")
            || ["remove", "delete", "revoke"].iter().any(|needle| path.contains(needle)))
}

fn concrete_authz_object_endpoint(
    profiles: &[ProjectAuthProfile],
    owner_role: &str,
    endpoint: &EndpointCandidate,
) -> Option<(EndpointCandidate, AuthzOwnedObject)> {
    if let Some(owned) = configured_owned_object_for_endpoint(profiles, owner_role, endpoint) {
        let object_id = owned.id.trim();
        if object_id.is_empty() {
            return None;
        }
        let mut object_endpoint = endpoint.clone();
        object_endpoint.path = path_with_first_param_value(&endpoint.path, object_id);
        object_endpoint.url = replace_path_in_url(&endpoint.url, &object_endpoint.path)
            .unwrap_or_else(|| endpoint.url.clone());
        let mut markers = Vec::new();
        if let Some(marker) = owned.marker.as_deref().filter(|s| !s.trim().is_empty()) {
            markers.push(marker.to_string());
        }
        markers.push(object_id.to_string());
        return Some((
            object_endpoint,
            AuthzOwnedObject {
                name: owned.name.clone(),
                owner_role: owner_role.to_string(),
                id: Some(object_id.to_string()),
                id_var: Some("object_id".to_string()),
                route: owned.route.clone(),
                positive_markers: markers,
            },
        ));
    }

    if endpoint.path.contains(':') || endpoint.path.contains('{') {
        return None;
    }
    let id = object_id_from_endpoint(endpoint);
    let mut markers = Vec::new();
    if let Some(id) = id.clone() {
        markers.push(id);
    }
    Some((
        endpoint.clone(),
        AuthzOwnedObject {
            name: object_name_from_path(&endpoint.path),
            owner_role: owner_role.to_string(),
            id,
            id_var: Some("object_id".to_string()),
            route: Some(endpoint.path.clone()),
            positive_markers: markers,
        },
    ))
}

fn configured_owned_object_for_endpoint<'a>(
    profiles: &'a [ProjectAuthProfile],
    owner_role: &str,
    endpoint: &EndpointCandidate,
) -> Option<&'a ProjectAuthOwnedObject> {
    let profile = profiles.iter().find(|profile| profile.role == owner_role)?;
    profile
        .owned_objects
        .iter()
        .find(|object| {
            object.route.as_deref().is_some_and(|route| {
                route_resource_key(route) == route_resource_key(&endpoint.path)
            })
        })
        .or_else(|| profile.owned_objects.first())
}

fn route_resource_key(path: &str) -> String {
    path.split('/')
        .filter(|part| {
            !part.is_empty()
                && !part.starts_with(':')
                && !(part.starts_with('{') && part.ends_with('}'))
        })
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("/")
}

fn path_with_first_param_value(path: &str, value: &str) -> String {
    path.split('/')
        .map(|part| {
            if part.starts_with(':') || (part.starts_with('{') && part.ends_with('}')) {
                value.to_string()
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn replace_path_in_url(url: &str, path: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port().map(|port| format!(":{port}")).unwrap_or_default();
    Some(format!(
        "{}://{}{}{}",
        parsed.scheme(),
        host,
        port,
        if path.starts_with('/') { path.to_string() } else { format!("/{path}") }
    ))
}

fn object_id_from_endpoint(endpoint: &EndpointCandidate) -> Option<String> {
    endpoint
        .path
        .split('/')
        .rev()
        .find(|part| part.chars().any(|ch| ch.is_ascii_digit()))
        .map(str::to_string)
}

fn object_name_from_path(path: &str) -> String {
    path.split('/')
        .filter(|part| !part.is_empty())
        .rev()
        .find(|part| {
            !part.chars().any(|ch| ch.is_ascii_digit())
                && !part.starts_with(':')
                && !(part.starts_with('{') && part.ends_with('}'))
        })
        .unwrap_or("object")
        .trim_matches(['{', '}', ':'])
        .to_string()
}

fn sensitive_markers(
    candidate: &PentestCandidateRecord,
    endpoint: &EndpointCandidate,
) -> Vec<String> {
    let text = candidate_text(candidate);
    let endpoint_path = endpoint.path.to_ascii_lowercase();
    let mut markers = Vec::new();
    if endpoint_path.contains("/api/dev/mail") || endpoint_path.contains("/dev/mail") {
        markers.push("mail".to_string());
    }
    if endpoint_path.contains("/api/admin/bug-reports") {
        markers.push("reports".to_string());
    }
    if endpoint_path.contains("/api/admin/users") {
        markers.push("users".to_string());
    }
    for (needle, marker) in [
        ("dev mail", "mail"),
        ("dev_mail", "mail"),
        ("smtp", "smtp"),
        ("debug", "debug"),
        ("stack", "stack"),
        ("trace", "trace"),
        ("swagger", "swagger"),
        ("openapi", "openapi"),
        ("admin", "admin"),
        ("config", "config"),
        ("settings", "settings"),
        ("token", "token"),
        ("secret", "secret"),
        ("account", "account"),
        ("email", "email"),
        ("tenant", "tenant"),
    ] {
        if text.contains(needle) || endpoint_path.contains(needle) {
            markers.push(marker.to_string());
        }
    }
    for component in &candidate.affected_components {
        for key in ["marker", "body_contains", "expected_marker", "positive_marker"] {
            if let Some(marker) = component.get(key).and_then(|v| v.as_str()) {
                markers.push(marker.to_string());
            }
        }
        if let Some(items) = component.get("positive_markers").and_then(|v| v.as_array()) {
            markers.extend(items.iter().filter_map(|v| v.as_str().map(str::to_string)));
        }
    }
    if markers.is_empty() {
        markers.push("id".to_string());
    }
    markers.sort();
    markers.dedup();
    markers.truncate(4);
    markers
}

fn trusted_header_name(candidate: &PentestCandidateRecord) -> String {
    let text = candidate_text(candidate);
    if text.contains("cf-access-authenticated-user-email") || text.contains("cf-access") {
        "Cf-Access-Authenticated-User-Email".to_string()
    } else if text.contains("x-original-user") {
        "X-Original-User".to_string()
    } else {
        "X-Forwarded-User".to_string()
    }
}

fn trusted_header_value(
    candidate: &PentestCandidateRecord,
    profiles: &[ProjectAuthProfile],
) -> Option<String> {
    let email_re =
        Regex::new(r#"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"#).expect("email regex");
    email_re.find(&candidate_text(candidate)).map(|m| m.as_str().to_string()).or_else(|| {
        profiles
            .iter()
            .find(|profile| {
                let role = profile.role.to_ascii_lowercase();
                contains_any(&role, &["admin", "owner", "staff"])
            })
            .and_then(|profile| profile.username.clone().filter(|value| email_re.is_match(value)))
    })
}

fn contextual_payload(
    kind: &str,
    transport: PayloadTransport,
    injection_point: &str,
    vuln_payload: &str,
    expected_signal: &str,
    benign_control: &str,
    state_changing: bool,
    why_this_confirms: &str,
) -> ContextualPayload {
    ContextualPayload {
        vuln_payload: vuln_payload.to_string(),
        vuln_oracle: expected_signal.to_string(),
        benign_payload: benign_control.to_string(),
        transport,
        injection_point: Some(injection_point.to_string()),
        encoding: Some("url/json/header context as generated by plan".to_string()),
        context: Some(kind.to_string()),
        expected_signal: Some(expected_signal.to_string()),
        oracle: Some(expected_signal.to_string()),
        benign_control: Some(benign_control.to_string()),
        state_changing,
        risk: Some(if state_changing { "state-changing" } else { "read-only" }.to_string()),
        cleanup_hint: None,
        reset_hint: state_changing.then(|| "run configured reset hook after probe".to_string()),
        why_this_confirms: Some(why_this_confirms.to_string()),
    }
}

fn append_query(url: &str, key: &str, value: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return url.to_string();
    };
    parsed.query_pairs_mut().append_pair(key, value);
    parsed.to_string()
}

fn redirect_param(candidate: &PentestCandidateRecord) -> String {
    if let Some(param) = candidate_param(candidate).filter(|param| param_looks_redirectish(param)) {
        return param;
    }
    let text = candidate_text(candidate);
    for (needle, param) in [
        ("next", "next"),
        ("redirect_uri", "redirect_uri"),
        ("return_url", "return_url"),
        ("url", "url"),
        ("redirect", "redirect"),
    ] {
        if text.contains(needle) {
            return param.to_string();
        }
    }
    "next".to_string()
}

fn candidate_param(candidate: &PentestCandidateRecord) -> Option<String> {
    candidate.affected_components.iter().find_map(|component| {
        let obj = component.as_object()?;
        obj.get("param")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| component_string_array(obj, "params").into_iter().next())
            .or_else(|| component_string_array(obj, "query_params").into_iter().next())
            .or_else(|| component_string_array(obj, "body_fields").into_iter().next())
    })
}

fn component_params(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut params = component_string_array(obj, "params");
    if let Some(param) = obj.get("param").and_then(|v| v.as_str()) {
        params.push(param.to_string());
    }
    params.extend(component_string_array(obj, "query_params"));
    params.sort();
    params.dedup();
    params
}

fn component_string_array(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Vec<String> {
    match obj.get(key) {
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str())
            .map(str::to_string)
            .filter(|value| !value.trim().is_empty())
            .collect(),
        Some(serde_json::Value::String(value)) if !value.trim().is_empty() => {
            vec![value.to_string()]
        }
        _ => Vec::new(),
    }
}

fn param_looks_redirectish(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    contains_any(&lower, &["next", "redirect", "return", "callback", "url", "continue"])
}

fn endpoint_preferring_admin(endpoints: &[EndpointCandidate]) -> Option<&EndpointCandidate> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.path.to_ascii_lowercase().contains("admin"))
        .or_else(|| endpoints.first())
}

fn endpoint_has_file_param(endpoint: &EndpointCandidate) -> bool {
    endpoint.params.iter().any(|param| param_looks_fileish(param))
        || endpoint.body_fields.iter().any(|field| param_looks_fileish(field))
        || endpoint.path.to_ascii_lowercase().contains("file")
}

fn param_looks_fileish(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    contains_any(&lower, &["file", "path", "template", "name", "download"])
}

fn route_params(path: &str) -> Vec<String> {
    path.split('/')
        .filter_map(|part| {
            part.strip_prefix(':')
                .or_else(|| part.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
                .map(str::to_string)
        })
        .collect()
}

fn candidate_source_path(candidate: &PentestCandidateRecord) -> Option<String> {
    candidate.affected_components.iter().find_map(|component| {
        component
            .get("path")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| component.get("file").and_then(|v| v.as_str()).map(str::to_string))
    })
}

fn candidate_text(candidate: &PentestCandidateRecord) -> String {
    format!(
        "{} {} {} {} {}",
        candidate.title,
        candidate.vuln_class,
        candidate.hypothesis,
        candidate.source,
        serde_json::to_string(&candidate.affected_components).unwrap_or_default()
    )
    .to_ascii_lowercase()
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn push_endpoint(out: &mut Vec<EndpointCandidate>, endpoint: EndpointCandidate) {
    if !out
        .iter()
        .any(|existing| existing.method == endpoint.method && existing.url == endpoint.url)
    {
        out.push(endpoint);
    }
}

fn endpoint_rank(endpoint: &EndpointCandidate) -> (u8, u8, usize, String) {
    let path = endpoint.path.to_ascii_lowercase();
    let source_priority = match endpoint.source.as_str() {
        "source_path" => 3,
        "candidate_text" => 2,
        "api_client" => 1,
        _ => 0,
    };
    let path_priority = if path.starts_with("/api/") {
        0
    } else if path.contains("admin") || path.contains("debug") || path.contains("dev") {
        1
    } else if path.contains("api") {
        2
    } else {
        3
    };
    let specificity_priority = usize::MAX.saturating_sub(path.len());
    (source_priority, path_priority, specificity_priority, endpoint.path.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_sessions::AuthSessionManager;
    use crate::pentest_tools::{
        execute_live_test_plan, ExploitAuditLog, ExploitSafetyPolicy, LiveVerifierOptions,
        ToolVerificationOutcome,
    };
    use nyctos_types::product::{RouteEvidence, RouteModel};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn candidate(class: &str, path: &str, title: &str) -> PentestCandidateRecord {
        PentestCandidateRecord {
            id: "pc-1".to_string(),
            run_id: "run-1".to_string(),
            project_id: "project-1".to_string(),
            source: "NyxSignal".to_string(),
            source_ids: vec!["sig-1".to_string()],
            title: title.to_string(),
            vuln_class: class.to_string(),
            severity_guess: "High".to_string(),
            affected_components: vec![serde_json::json!({"repo":"app","path": path, "line": 12})],
            hypothesis: title.to_string(),
            test_plan: "Derive a safe live HTTP/browser confirmation.".to_string(),
            status: "NeedsLiveTest".to_string(),
            rejection_reason: None,
            confidence: 0.7,
            trace_id: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn verifier_options(base: &str) -> LiveVerifierOptions {
        LiveVerifierOptions {
            target_urls: vec![base.to_string()],
            auth_profiles: Vec::new(),
            auth_session_manager: AuthSessionManager::default(),
            auth_artifact_dir: std::env::temp_dir().join("nyctos-live-planning-auth-test"),
            auth_workspace_paths: Vec::new(),
            auth_env_overrides: BTreeMap::new(),
            browser_artifact_dir: None,
            browser_checks_enabled: false,
            policy: ExploitSafetyPolicy {
                requests_per_second: 1000,
                ..ExploitSafetyPolicy::default()
            },
            audit_log: ExploitAuditLog::default(),
        }
    }

    fn auth_profile_with_object(
        role: &str,
        object: Option<ProjectAuthOwnedObject>,
    ) -> ProjectAuthProfile {
        ProjectAuthProfile {
            role: role.to_string(),
            role_aliases: Vec::new(),
            mode: nyctos_types::project::ProjectAuthMode::HeaderInjection,
            label: None,
            tenant: None,
            session_cache_ttl_seconds: None,
            session_import_path: None,
            login_url: None,
            username: None,
            username_env: None,
            login_email_env: None,
            password_env: None,
            password_secret_ref: None,
            cookie_env: None,
            bearer_token_env: None,
            headers: Vec::new(),
            otp_source: None,
            post_login_assertions: Vec::new(),
            post_login_assertion: None,
            custom_command: None,
            owned_objects: object.into_iter().collect(),
        }
    }

    #[test]
    fn infers_admin_endpoint_from_handler_path() {
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: None,
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let plan = synth.synthesize(&candidate(
            "DEBUG_ENDPOINT",
            "src/handlers/admin.rs",
            "Admin debug endpoint exposes diagnostics",
        ));
        match plan {
            LiveTestPlan::SingleHttp(plan) => {
                assert!(
                    plan.request.url.contains("/admin") || plan.request.url.contains("/api/admin")
                );
                assert!(plan.oracle.has_positive_evidence());
            }
            other => panic!("expected single http plan, got {other:?}"),
        }
    }

    #[test]
    fn dom_xss_is_no_plan_when_browser_disabled() {
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: None,
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let plan =
            synth.synthesize(&candidate("DOM_XSS", "src/app/search.tsx", "DOM XSS via innerHTML"));
        assert_eq!(plan.no_plan_reason().unwrap().code, NoPlanReasonCode::BrowserDisabled);
    }

    #[test]
    fn route_model_endpoint_becomes_debug_exposure_plan() {
        let model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/dev/mail".to_string(),
                repo: Some("app".to_string()),
                handler_file: Some("src/handlers/dev_mail.rs".to_string()),
                line: Some(9),
                params: Vec::new(),
                middleware: Vec::new(),
                auth_checks: Vec::new(),
                role_checks: Vec::new(),
                body_fields: Vec::new(),
                state_changing: false,
                confidence: 0.9,
                evidence: vec![RouteEvidence {
                    path: "src/handlers/dev_mail.rs".to_string(),
                    line: Some(9),
                    snippet: "router.get(\"/api/dev/mail\")".to_string(),
                }],
                ..RouteModelEndpoint::default()
            }],
            ..RouteModel::default()
        };
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let plan = synth.synthesize(&candidate(
            "SENSITIVE_DATA_EXPOSURE",
            "src/handlers/dev_mail.rs",
            "Dev mail endpoint exposes email contents",
        ));
        match plan {
            LiveTestPlan::SingleHttp(plan) => {
                assert_eq!(plan.request.url, "http://localhost:3000/api/dev/mail");
                assert!(plan.oracle.body_contains.iter().any(|m| m == "mail"));
            }
            other => panic!("expected single http plan, got {other:?}"),
        }
    }

    #[test]
    fn nyx_open_redirect_component_becomes_executable_plan() {
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: None,
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let mut candidate =
            candidate("OPEN_REDIRECT", "src/auth/callback.ts", "Potential open redirect from Nyx");
        candidate.affected_components = vec![serde_json::json!({
            "kind": "nyx_signal",
            "path": "src/auth/callback.ts",
            "route": "/login/callback",
            "url_path": "/login/callback",
            "method": "GET",
            "param": "next",
            "sink": "redirect",
        })];

        let plan = synth.synthesize(&candidate);

        match plan {
            LiveTestPlan::SingleHttp(plan) => {
                assert_eq!(plan.request.path.as_deref(), Some("/login/callback"));
                assert!(plan.request.url.starts_with("http://localhost:3000/login/callback?"));
                assert!(plan.request.url.contains("next="));
                assert_eq!(
                    plan.request.payload.as_ref().and_then(|p| p.injection_point.as_deref()),
                    Some("next")
                );
                assert_eq!(
                    plan.oracle.header_contains.get("location").map(String::as_str),
                    Some("nyctos.invalid")
                );
            }
            other => panic!("expected open redirect HTTP plan, got {other:?}"),
        }
    }

    #[test]
    fn nyx_config_exposure_component_becomes_safe_http_plan() {
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: None,
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let mut candidate = candidate(
            "CONFIG_EXPOSURE",
            "src/routes/config.ts",
            "Potential configuration exposure",
        );
        candidate.affected_components = vec![serde_json::json!({
            "kind": "nyx_signal",
            "path": "src/routes/config.ts",
            "route": "/api/config",
            "url_path": "/api/config",
            "method": "GET",
            "sink": "json(config)",
        })];
        candidate.hypothesis =
            "Configuration route may expose config and secret markers.".to_string();

        let plan = synth.synthesize(&candidate);

        match plan {
            LiveTestPlan::SingleHttp(plan) => {
                assert_eq!(plan.request.url, "http://localhost:3000/api/config");
                assert!(plan.oracle.body_contains.iter().any(|m| m == "config"));
            }
            other => panic!("expected config exposure HTTP plan, got {other:?}"),
        }
    }

    #[test]
    fn nyx_auth_bypass_without_auth_profiles_is_no_plan_aware() {
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: None,
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let mut candidate =
            candidate("AUTH_BYPASS", "src/routes/admin.ts", "Potential auth bypass");
        candidate.affected_components = vec![serde_json::json!({
            "kind": "nyx_signal",
            "path": "src/routes/admin.ts",
            "route": "/admin",
            "url_path": "/admin",
            "method": "GET",
        })];

        let plan = synth.synthesize(&candidate);

        assert_eq!(plan.no_plan_reason().unwrap().code, NoPlanReasonCode::AuthMissing);
    }

    #[test]
    fn trusted_cf_access_header_bypass_gets_http_plan_without_auth_profile() {
        let model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/admin/users/search".to_string(),
                repo: Some("app".to_string()),
                handler_file: Some("src/handlers/admin.rs".to_string()),
                line: Some(42),
                params: Vec::new(),
                middleware: Vec::new(),
                auth_checks: Vec::new(),
                role_checks: Vec::new(),
                body_fields: Vec::new(),
                state_changing: false,
                confidence: 0.9,
                evidence: Vec::new(),
                ..RouteModelEndpoint::default()
            }],
            ..RouteModel::default()
        };
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let mut candidate = candidate(
            "AUTH_BYPASS",
            "src/handlers/admin.rs",
            "Admin gate trusts Cf-Access-Authenticated-User-Email",
        );
        candidate.hypothesis =
            "Trusted header bypass with Cf-Access-Authenticated-User-Email: eli@example.com"
                .to_string();

        let plan = synth.synthesize(&candidate);

        match plan {
            LiveTestPlan::SingleHttp(plan) => {
                assert_eq!(plan.request.url, "http://localhost:3000/api/admin/users/search");
                assert_eq!(
                    plan.request.headers.get("Cf-Access-Authenticated-User-Email"),
                    Some(&"eli@example.com".to_string())
                );
                assert!(plan.baseline.is_some());
                assert!(plan.oracle.body_contains.iter().any(|m| m == "users"));
            }
            other => panic!("expected single HTTP trusted-header plan, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_inference_ignores_local_filesystem_paths() {
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: None,
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let candidate = candidate(
            "CONFIG_EXPOSURE",
            "src/auth.rs",
            "Potential configuration exposure: /Users/elipeter/Library/Application Support/nyctos/src/auth.rs:46",
        );

        let plan = synth.synthesize(&candidate);

        assert_eq!(plan.no_plan_reason().unwrap().code, NoPlanReasonCode::RouteNotInferred);
    }

    #[test]
    fn idor_with_configured_owned_object_becomes_authz_object_plan() {
        let model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/projects/{id}".to_string(),
                repo: Some("app".to_string()),
                handler_file: Some("src/routes/projects.rs".to_string()),
                line: Some(42),
                params: vec!["id".to_string()],
                middleware: Vec::new(),
                auth_checks: Vec::new(),
                role_checks: Vec::new(),
                body_fields: Vec::new(),
                state_changing: false,
                confidence: 0.9,
                evidence: Vec::new(),
                ..RouteModelEndpoint::default()
            }],
            ..RouteModel::default()
        };
        let targets = vec!["http://localhost:3000".to_string()];
        let owner_object = ProjectAuthOwnedObject {
            name: "project".to_string(),
            id: "proj-user-a-1".to_string(),
            route: Some("/api/projects/{id}".to_string()),
            marker: Some("nyctos-owned-project".to_string()),
        };
        let auth = vec![
            auth_profile_with_object("user_a", Some(owner_object)),
            auth_profile_with_object("user_b", None),
        ];
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let candidate = candidate(
            "IDOR",
            "src/routes/projects.rs",
            "Project detail route may not enforce object ownership",
        );

        let plan = synth.synthesize(&candidate);

        match plan {
            LiveTestPlan::AuthzObjectOwnership(plan) => {
                assert_eq!(plan.object.owner_role, "user_a");
                assert_eq!(plan.accessor_role, "user_b");
                assert_eq!(
                    plan.owner_request.url,
                    "http://localhost:3000/api/projects/proj-user-a-1"
                );
                assert!(plan.oracle.positive_markers.iter().any(|m| m == "nyctos-owned-project"));
            }
            other => panic!("expected authz object ownership plan, got {other:?}"),
        }
    }

    #[test]
    fn idor_uses_creator_member_roles_when_user_a_user_b_are_absent() {
        let model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/projects/{id}".to_string(),
                handler_file: Some("src/routes/projects.rs".to_string()),
                params: vec!["id".to_string()],
                state_changing: false,
                confidence: 0.9,
                ..RouteModelEndpoint::default()
            }],
            ..RouteModel::default()
        };
        let targets = vec!["http://localhost:3000".to_string()];
        let owner_object = ProjectAuthOwnedObject {
            name: "project".to_string(),
            id: "proj-creator-1".to_string(),
            route: Some("/api/projects/{id}".to_string()),
            marker: Some("nyctos-owned-project".to_string()),
        };
        let mut creator = auth_profile_with_object("creator", Some(owner_object));
        creator.bearer_token_env = Some("NYCTOS_TEST_CREATOR_TOKEN".to_string());
        let mut member = auth_profile_with_object("member", None);
        member.bearer_token_env = Some("NYCTOS_TEST_MEMBER_TOKEN".to_string());
        let auth = vec![creator, member];
        let env = discover_env_capabilities(EnvCapabilityDiscoveryInput {
            target_urls: &targets,
            auth_profiles: &auth,
            auth_env_overrides: &BTreeMap::from([
                ("NYCTOS_TEST_CREATOR_TOKEN".to_string(), "creator-token".to_string()),
                ("NYCTOS_TEST_MEMBER_TOKEN".to_string(), "member-token".to_string()),
            ]),
            browser_checks_enabled: false,
            browser_available: false,
            seed_supported: true,
            reset_supported: true,
            exploit_mode_enabled: false,
            allow_state_changing: false,
            dry_run: false,
        });
        assert_eq!(
            env.ready_auth_role_pair().map(|pair| pair.owner_role.as_str()),
            Some("creator")
        );
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: Some(&env),
        });

        let plan = synth.synthesize(&candidate(
            "IDOR",
            "src/routes/projects.rs",
            "Project detail route may not enforce horizontal authorization",
        ));

        match plan {
            LiveTestPlan::AuthzObjectOwnership(plan) => {
                assert_eq!(plan.object.owner_role, "creator");
                assert_eq!(plan.accessor_role, "member");
                assert_eq!(plan.owner_request.role, "creator");
                assert_eq!(plan.accessor_request.role, "member");
            }
            other => panic!("expected creator/member authz plan, got {other:?}"),
        }
    }

    #[test]
    fn capability_report_turns_missing_auth_env_into_setup_missing_no_plan() {
        let model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/projects/{id}".to_string(),
                repo: Some("app".to_string()),
                handler_file: Some("src/routes/projects.rs".to_string()),
                line: Some(42),
                params: vec!["id".to_string()],
                state_changing: false,
                confidence: 0.9,
                ..RouteModelEndpoint::default()
            }],
            ..RouteModel::default()
        };
        let targets = vec!["http://localhost:3000".to_string()];
        let owner_object = ProjectAuthOwnedObject {
            name: "project".to_string(),
            id: "proj-user-a-1".to_string(),
            route: Some("/api/projects/{id}".to_string()),
            marker: Some("nyctos-owned-project".to_string()),
        };
        let mut user_a = auth_profile_with_object("user_a", Some(owner_object));
        user_a.bearer_token_env = Some("NYCTOS_TEST_MISSING_USER_A_TOKEN".to_string());
        let mut user_b = auth_profile_with_object("user_b", None);
        user_b.bearer_token_env = Some("NYCTOS_TEST_USER_B_TOKEN".to_string());
        let auth = vec![user_a, user_b];
        let env = discover_env_capabilities(EnvCapabilityDiscoveryInput {
            target_urls: &targets,
            auth_profiles: &auth,
            auth_env_overrides: &BTreeMap::from([(
                "NYCTOS_TEST_USER_B_TOKEN".to_string(),
                "redacted-token".to_string(),
            )]),
            browser_checks_enabled: false,
            browser_available: false,
            seed_supported: true,
            reset_supported: true,
            exploit_mode_enabled: false,
            allow_state_changing: false,
            dry_run: false,
        });
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: Some(&env),
        });

        let plan = synth.synthesize(&candidate(
            "IDOR",
            "src/routes/projects.rs",
            "Project detail route may not enforce object ownership",
        ));

        let reason = plan.no_plan_reason().expect("setup no-plan");
        assert_eq!(reason.code, NoPlanReasonCode::SetupMissing);
        assert!(reason.message.contains("missing env"));
        assert_eq!(reason.context.get("missing_auth_roles").map(String::as_str), Some("user_a"));
    }

    #[test]
    fn replan_after_failure_is_bounded_to_retryable_failure_codes() {
        let model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/dev/mail".to_string(),
                repo: Some("app".to_string()),
                handler_file: Some("src/handlers/dev_mail.rs".to_string()),
                line: Some(9),
                params: Vec::new(),
                middleware: Vec::new(),
                auth_checks: Vec::new(),
                role_checks: Vec::new(),
                body_fields: Vec::new(),
                state_changing: false,
                confidence: 0.9,
                evidence: Vec::new(),
                ..RouteModelEndpoint::default()
            }],
            ..RouteModel::default()
        };
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let candidate = candidate(
            "SENSITIVE_DATA_EXPOSURE",
            "src/handlers/dev_mail.rs",
            "Dev mail endpoint exposes email contents",
        );

        assert!(matches!(
            synth.replan_after_failure(&candidate, Some("bad_endpoint")),
            Some(LiveTestPlan::SingleHttp(_))
        ));
        assert!(matches!(
            synth.replan_after_failure(&candidate, Some("auth_missing")),
            Some(LiveTestPlan::SingleHttp(_))
        ));
        assert!(synth.replan_after_failure(&candidate, Some("browser_disabled")).is_none());
    }

    #[test]
    fn bad_endpoint_replan_uses_alternate_route_model_match() {
        let targets = vec!["http://localhost:3000".to_string()];
        let bad_url = "http://localhost:3000/api/dev/mail-old";
        let model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/dev/mail".to_string(),
                handler_file: Some("src/handlers/dev_mail.rs".to_string()),
                state_changing: false,
                confidence: 0.95,
                ..RouteModelEndpoint::default()
            }],
            ..RouteModel::default()
        };
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let mut candidate = candidate(
            "SENSITIVE_DATA_EXPOSURE",
            "src/handlers/dev_mail.rs",
            "Dev mail endpoint exposes email contents",
        );
        candidate.affected_components.push(serde_json::json!({
            "method": "GET",
            "url": bad_url,
        }));
        candidate.test_plan = serde_json::json!({
            "kind": "single_http",
            "request": {"method": "GET", "url": bad_url},
            "oracle": {"body_contains": ["mail"]}
        })
        .to_string();

        let replan = synth
            .replan_after_failure(&candidate, Some("bad_endpoint"))
            .expect("alternate route plan");

        match replan {
            LiveTestPlan::SingleHttp(plan) => {
                assert_eq!(plan.request.url, "http://localhost:3000/api/dev/mail");
            }
            other => panic!("expected single HTTP replan, got {other:?}"),
        }
    }

    #[test]
    fn auth_missing_replan_uses_role_aliases() {
        let targets = vec!["http://localhost:3000".to_string()];
        let mut profile = auth_profile_with_object("app_owner", None);
        profile.role_aliases = vec!["admin".to_string(), "staff".to_string()];
        let auth = vec![profile];
        let model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/admin/users".to_string(),
                handler_file: Some("src/routes/admin.rs".to_string()),
                state_changing: false,
                confidence: 0.95,
                ..RouteModelEndpoint::default()
            }],
            ..RouteModel::default()
        };
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let candidate =
            candidate("AUTH_BYPASS", "src/routes/admin.rs", "Admin endpoint auth bypass");

        let replan = synth.replan_after_failure(&candidate, Some("auth_missing"));

        match replan {
            Some(LiveTestPlan::DifferentialHttp(plan)) => {
                assert_eq!(plan.steps[0].role, "app_owner");
            }
            other => panic!("expected aliased auth differential replan, got {other:?}"),
        }
    }

    #[test]
    fn weak_oracle_replan_uses_derived_positive_marker() {
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/dev/mail".to_string(),
                handler_file: Some("src/handlers/dev_mail.rs".to_string()),
                state_changing: false,
                confidence: 0.95,
                ..RouteModelEndpoint::default()
            }],
            ..RouteModel::default()
        };
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let mut candidate = candidate(
            "SENSITIVE_DATA_EXPOSURE",
            "src/handlers/dev_mail.rs",
            "Sensitive endpoint exposes derived marker",
        );
        candidate.affected_components.push(serde_json::json!({
            "positive_marker": "smtp"
        }));

        let replan = synth.replan_after_failure(&candidate, Some("weak_oracle"));

        match replan {
            Some(LiveTestPlan::SingleHttp(plan)) => {
                assert!(plan.oracle.body_contains.iter().any(|m| m == "smtp"));
            }
            other => panic!("expected marker-aware replan, got {other:?}"),
        }
    }

    #[test]
    fn browser_disabled_path_is_setup_missing_with_capabilities() {
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let capabilities = discover_env_capabilities(EnvCapabilityDiscoveryInput {
            target_urls: &targets,
            auth_profiles: &auth,
            auth_env_overrides: &BTreeMap::new(),
            browser_checks_enabled: true,
            browser_available: false,
            seed_supported: false,
            reset_supported: false,
            exploit_mode_enabled: false,
            allow_state_changing: false,
            dry_run: false,
        });
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: None,
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: true,
            allow_state_changing: false,
            capabilities: Some(&capabilities),
        });
        let candidate = candidate("DOM_XSS", "src/app/search.tsx", "DOM XSS in search");

        match synth.synthesize(&candidate) {
            LiveTestPlan::NoPlan(plan) => {
                assert_eq!(plan.no_plan_reason.code, NoPlanReasonCode::SetupMissing);
                assert!(plan.no_plan_reason.message.contains("browser"));
            }
            other => panic!("expected setup-missing no-plan, got {other:?}"),
        }
    }

    #[test]
    fn planner_emits_stateful_invite_lifecycle_recipe_when_gates_ready() {
        let targets = vec!["http://localhost:3000".to_string()];
        let mut owner = auth_profile_with_object("owner", None);
        owner.bearer_token_env = Some("OWNER_TOKEN".to_string());
        let mut member = auth_profile_with_object("member", None);
        member.bearer_token_env = Some("MEMBER_TOKEN".to_string());
        let auth = vec![owner, member];
        let auth_env = BTreeMap::from([
            ("OWNER_TOKEN".to_string(), "owner-token".to_string()),
            ("MEMBER_TOKEN".to_string(), "member-token".to_string()),
        ]);
        let capabilities = discover_env_capabilities(EnvCapabilityDiscoveryInput {
            target_urls: &targets,
            auth_profiles: &auth,
            auth_env_overrides: &auth_env,
            browser_checks_enabled: false,
            browser_available: false,
            seed_supported: true,
            reset_supported: true,
            exploit_mode_enabled: true,
            allow_state_changing: true,
            dry_run: false,
        });
        let model = RouteModel {
            backend_routes: vec![
                RouteModelEndpoint {
                    method: "POST".to_string(),
                    path: "/api/trips/:trip_id/invites".to_string(),
                    params: vec!["trip_id".to_string()],
                    state_changing: true,
                    confidence: 0.95,
                    ..RouteModelEndpoint::default()
                },
                RouteModelEndpoint {
                    method: "POST".to_string(),
                    path: "/api/trips/invites/:token/accept".to_string(),
                    params: vec!["token".to_string()],
                    state_changing: true,
                    confidence: 0.95,
                    ..RouteModelEndpoint::default()
                },
                RouteModelEndpoint {
                    method: "DELETE".to_string(),
                    path: "/api/trips/invites/:token/cancel".to_string(),
                    params: vec!["token".to_string()],
                    state_changing: true,
                    confidence: 0.95,
                    ..RouteModelEndpoint::default()
                },
            ],
            ..RouteModel::default()
        };
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: true,
            capabilities: Some(&capabilities),
        });
        let candidate = candidate(
            "BUSINESS_LOGIC_ABUSE",
            "src/routes/invites.rs",
            "Trip invite stale inviter cancel after invite acceptance",
        );

        match synth.synthesize(&candidate) {
            LiveTestPlan::HttpWorkflow(plan) => {
                assert_eq!(plan.recipe.as_ref().unwrap().id, "trip_invite_stale_inviter_cancel");
                assert_eq!(plan.steps[0].purpose, Some(HttpWorkflowStepPurpose::Seed));
                assert_eq!(plan.steps[1].purpose, Some(HttpWorkflowStepPurpose::StateTransition));
                assert_eq!(plan.steps[2].purpose, Some(HttpWorkflowStepPurpose::Exploit));
                assert!(plan.steps[2].url.contains("{{invite_token}}"));
                LiveTestPlan::HttpWorkflow(plan).validate().unwrap();
            }
            other => panic!("expected stateful lifecycle workflow, got {other:?}"),
        }
    }

    #[test]
    fn planner_returns_setup_missing_reset_hook_for_mutating_recipe_without_cleanup() {
        let targets = vec!["http://localhost:3000".to_string()];
        let mut owner = auth_profile_with_object("owner", None);
        owner.bearer_token_env = Some("OWNER_TOKEN".to_string());
        let mut member = auth_profile_with_object("member", None);
        member.bearer_token_env = Some("MEMBER_TOKEN".to_string());
        let auth = vec![owner, member];
        let auth_env = BTreeMap::from([
            ("OWNER_TOKEN".to_string(), "owner-token".to_string()),
            ("MEMBER_TOKEN".to_string(), "member-token".to_string()),
        ]);
        let capabilities = discover_env_capabilities(EnvCapabilityDiscoveryInput {
            target_urls: &targets,
            auth_profiles: &auth,
            auth_env_overrides: &auth_env,
            browser_checks_enabled: false,
            browser_available: false,
            seed_supported: true,
            reset_supported: false,
            exploit_mode_enabled: true,
            allow_state_changing: true,
            dry_run: false,
        });
        let model = RouteModel::default();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: true,
            capabilities: Some(&capabilities),
        });
        let candidate = candidate(
            "BUSINESS_LOGIC_ABUSE",
            "src/routes/invites.rs",
            "Finalized explorer invite token acceptance",
        );

        match synth.synthesize(&candidate) {
            LiveTestPlan::NoPlan(plan) => {
                assert_eq!(plan.no_plan_reason.code, NoPlanReasonCode::SetupMissing);
                assert_eq!(
                    plan.no_plan_reason.context.get("setup_missing").map(String::as_str),
                    Some("ResetHook")
                );
            }
            other => panic!("expected setup-missing reset hook no-plan, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn realistic_debug_candidate_synthesizes_and_executes_safe_http_plan() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ordinary home page"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/dev/mail"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"mail":[{"email":"alice@example.test"}],"smtp":"dev"}"#),
            )
            .mount(&server)
            .await;

        let model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/dev/mail".to_string(),
                repo: Some("app".to_string()),
                handler_file: Some("src/handlers/dev_mail.rs".to_string()),
                line: Some(9),
                params: Vec::new(),
                middleware: Vec::new(),
                auth_checks: Vec::new(),
                role_checks: Vec::new(),
                body_fields: Vec::new(),
                state_changing: false,
                confidence: 0.95,
                evidence: vec![RouteEvidence {
                    path: "src/handlers/dev_mail.rs".to_string(),
                    line: Some(9),
                    snippet: "router.get(\"/api/dev/mail\")".to_string(),
                }],
                ..RouteModelEndpoint::default()
            }],
            ..RouteModel::default()
        };
        let targets = vec![server.uri()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
            capabilities: None,
        });
        let candidate = candidate(
            "SENSITIVE_DATA_EXPOSURE",
            "src/handlers/dev_mail.rs",
            "Dev mail endpoint exposes email contents",
        );
        let plan = synth.synthesize(&candidate);
        let plan_json = serde_json::to_string(&plan).unwrap();

        let outcome =
            execute_live_test_plan(&plan_json, &verifier_options(&targets[0])).await.unwrap();

        match outcome {
            ToolVerificationOutcome::Confirmed { oracle, response, .. } => {
                assert_eq!(oracle["success"], true);
                assert_eq!(oracle["baseline_clean"], true);
                assert_eq!(oracle["vuln_success"], true);
                assert_eq!(response["baseline"]["status"], 200);
                assert_eq!(response["response"]["status"], 200);
            }
            other => panic!("expected confirmed safe local HTTP plan, got {other:?}"),
        }
    }
}
