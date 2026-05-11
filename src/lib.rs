#![deny(unreachable_pub)]

mod artifact_decision;
mod bench;
mod core_runtime;
mod download;
mod evidence_ledger;
mod github_intent;
mod history;
mod releases;
mod source_adapter;
mod source_spec;
mod source_trust;
mod staged_release;
mod trust_center;
mod trust_policy;
mod update_apply_bundle;
mod update_apply_helper;
mod update_apply_plan;
mod update_apply_readiness;
mod update_candidate;
mod url_policy;
mod verification;
mod verifier_adapter;

pub mod backend_contract;
pub mod ui_projection;
