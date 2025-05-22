use std::collections::HashSet;

use anyhow::{anyhow, Result};
use guest::prelude::*;
use k8s_openapi::api::core::v1 as apicore;
use kubewarden_policy_sdk::wapc_guest as guest;
extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use crate::settings::Rule;

const ANY_IN_ERROR_MSG: &str =
    "Resource must have at least one of the required environment variables specified by the validation rule. None of the expected environment variables were found:";
const ANY_NOT_IN_ERROR_MSG: &str =
    "Resource must not have any of the environment variables specified in the validation rule. The following invalid environment variables were found:";
const ALL_ARE_USED_ERROR_MSG: &str =
    "Resource is missing required environment variables as specified in the validation rules. The following environment variables are missing:";
const NOT_ALL_ARE_USED_ERROR_MSG: &str =
    "Resource has conflicting environment variables set according to the validation rules. The following environment variables should not be set together:";

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<settings::Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate_envvar_with_rule(rule: &Rule, env_vars: &[apicore::EnvVar]) -> Result<()> {
    let error_message: String;
    let resource_env_var_names: HashSet<String> =
        env_vars.iter().map(|envvar| envvar.name.clone()).collect();

    match rule.reject {
        settings::Operator::ContainsAllOf => {
            if !rule
                .environment_variables
                .is_subset(&resource_env_var_names)
            {
                let missing_envvar = rule
                    .environment_variables
                    .difference(&resource_env_var_names)
                    .cloned()
                    .collect::<Vec<String>>()
                    .join(", ");
                error_message = format!("{ALL_ARE_USED_ERROR_MSG} {missing_envvar}");
                return Err(anyhow!(error_message));
            }
            Ok(())
        }
        settings::Operator::DoesNotContainAllOf => {
            if rule
                .environment_variables
                .is_subset(&resource_env_var_names)
            {
                let invalid_envvars = rule
                    .environment_variables
                    .clone()
                    .into_iter()
                    .collect::<Vec<String>>()
                    .join(", ");
                error_message = format!("{NOT_ALL_ARE_USED_ERROR_MSG} {invalid_envvars}");
                return Err(anyhow!(error_message));
            }
            Ok(())
        }
        settings::Operator::ContainsAnyOf => {
            if rule
                .environment_variables
                .is_disjoint(&resource_env_var_names)
            {
                let missing_envvar = rule
                    .environment_variables
                    .clone()
                    .into_iter()
                    .collect::<Vec<String>>()
                    .join(", ");
                error_message = format!("{ANY_IN_ERROR_MSG} {missing_envvar}");
                return Err(anyhow!(error_message));
            }
            Ok(())
        }
        settings::Operator::DoesNotContainAnyOf => {
            if !rule
                .environment_variables
                .is_disjoint(&resource_env_var_names)
            {
                let invalid_envvars = rule
                    .environment_variables
                    .intersection(&resource_env_var_names)
                    .cloned()
                    .collect::<Vec<String>>()
                    .join(", ");
                error_message = format!("{ANY_NOT_IN_ERROR_MSG} {invalid_envvars}");
                return Err(anyhow!(error_message));
            }
            Ok(())
        }
    }
}

fn validate_environment_variables(
    pod: &apicore::PodSpec,
    settings: &settings::Settings,
) -> Result<()> {
    for container in pod.containers.iter() {
        for rule in settings.rules.iter() {
            if let Some(envvar) = &container.env {
                validate_envvar_with_rule(rule, envvar)?;
            }
        }
    }
    if let Some(init_containers) = &pod.init_containers {
        for container in init_containers.iter() {
            for rule in settings.rules.iter() {
                if let Some(envvar) = &container.env {
                    validate_envvar_with_rule(rule, envvar)?;
                }
            }
        }
    }
    if let Some(ephemeral_containers) = &pod.ephemeral_containers {
        for container in ephemeral_containers.iter() {
            for rule in settings.rules.iter() {
                if let Some(envvar) = &container.env {
                    validate_envvar_with_rule(rule, envvar)?;
                }
            }
        }
    }
    Ok(())
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<settings::Settings> =
        ValidationRequest::new(payload)?;
    match validation_request.extract_pod_spec_from_object() {
        Ok(pod_spec) => {
            if let Some(pod_spec) = pod_spec {
                return match validate_environment_variables(&pod_spec, &validation_request.settings)
                {
                    Ok(_) => kubewarden::accept_request(),
                    Err(err) => kubewarden::reject_request(Some(err.to_string()), None, None, None),
                };
            };
            // If there is not pod spec, just accept it. There is no data to be
            // validated.
            kubewarden::accept_request()
        }
        Err(_) => kubewarden::reject_request(
            Some("Cannot parse validation request".to_string()),
            None,
            None,
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::collections::HashSet;

    #[rstest]
    #[case::any_in(Rule {
            reject: settings::Operator::ContainsAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::any_in(Rule {
            reject: settings::Operator::ContainsAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::any_in(Rule {
            reject: settings::Operator::ContainsAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::any_in(Rule {
            reject: settings::Operator::ContainsAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::any_in(Rule {
            reject: settings::Operator::ContainsAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::any_in(Rule {
            reject: settings::Operator::ContainsAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::any_in(Rule {
            reject: settings::Operator::ContainsAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::any_in(Rule {
            reject: settings::Operator::ContainsAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::any_in(Rule {
            reject: settings::Operator::ContainsAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![ ], false)]
    #[case::any_not_in(Rule {
            reject: settings::Operator::DoesNotContainAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::any_not_in(Rule {
            reject: settings::Operator::DoesNotContainAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::any_not_in(Rule {
            reject: settings::Operator::DoesNotContainAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::any_not_in(Rule {
            reject: settings::Operator::DoesNotContainAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::any_not_in(Rule {
            reject: settings::Operator::DoesNotContainAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::any_not_in(Rule {
            reject: settings::Operator::DoesNotContainAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::any_not_in(Rule {
            reject: settings::Operator::DoesNotContainAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::any_not_in(Rule {
            reject: settings::Operator::DoesNotContainAnyOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![ ], true)]
    #[case::all_are_used(Rule {
            reject: settings::Operator::ContainsAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::all_are_used(Rule {
            reject: settings::Operator::ContainsAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::all_are_used(Rule {
            reject: settings::Operator::ContainsAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::all_are_used(Rule {
            reject: settings::Operator::ContainsAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::all_are_used(Rule {
            reject: settings::Operator::ContainsAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::all_are_used(Rule {
            reject: settings::Operator::ContainsAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::all_are_used(Rule {
            reject: settings::Operator::ContainsAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::all_are_used(Rule {
            reject: settings::Operator::ContainsAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![ ], false)]
    #[case::not_all_are_used(Rule {
            reject: settings::Operator::DoesNotContainAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::not_all_are_used(Rule {
            reject: settings::Operator::DoesNotContainAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::not_all_are_used(Rule {
            reject: settings::Operator::DoesNotContainAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::not_all_are_used(Rule {
            reject: settings::Operator::DoesNotContainAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], false)]
    #[case::not_all_are_used(Rule {
            reject: settings::Operator::DoesNotContainAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::not_all_are_used(Rule {
            reject: settings::Operator::DoesNotContainAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "a".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::not_all_are_used(Rule {
            reject: settings::Operator::DoesNotContainAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![
            apicore::EnvVar {
                name: "b".to_string(),
                value: None,
                ..Default::default()
            },
            apicore::EnvVar {
                name: "c".to_string(),
                value: None,
                ..Default::default()
            },
        ], true)]
    #[case::not_all_are_used(Rule {
            reject: settings::Operator::DoesNotContainAllOf,
            environment_variables: HashSet::from([
            "a".to_owned(),"b".to_owned()
            ]),
        }, vec![ ], true)]
    fn tests(#[case] rule: Rule, #[case] envvar: Vec<apicore::EnvVar>, #[case] is_ok: bool) {
        let result = validate_envvar_with_rule(&rule, &envvar);
        assert_eq!(result.is_ok(), is_ok);
    }
}
