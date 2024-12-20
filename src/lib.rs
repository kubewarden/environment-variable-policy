use std::collections::HashSet;

use anyhow::{anyhow, Result};
use guest::prelude::*;
use k8s_openapi::api::core::v1 as apicore;
use kubewarden_policy_sdk::wapc_guest as guest;
extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use crate::settings::Rule;

const ALL_ARE_USED_ERROR_MSG: &str =
    "Resource cannot have all the environment variables from the rule defined. Invalid environment variables found: ";
const NOT_ALL_ARE_USED_ERROR_MSG: &str =
    "Resource should have all the environment variables from the rule defined. Invalid environment variables found: ";
const ANY_IN_ERROR_MSG: &str =
    "Resource cannot define any of the environment variables from the rule. Invalid environment variables found:";
const ANY_NOT_IN_ERROR_MSG: &str =
    "Resource should define at least one of the environment variables from the rule. Invalid environment variables found:";

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<settings::Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate_envvar_with_rule(rule: &Rule, env_vars: &[apicore::EnvVar]) -> Result<()> {
    let validation_envvar: HashSet<settings::EnvVar> = rule
        .environment_variables
        .clone()
        .into_iter()
        .filter(|envvar| envvar.value.is_some())
        .collect();
    let validation_envvar_with_values_names: HashSet<String> = validation_envvar
        .iter()
        .filter_map(|envvar| {
            if envvar.value.is_none() {
                None
            } else {
                Some(envvar.name.clone())
            }
        })
        .collect();

    let validation_envvar_names: HashSet<String> = rule
        .environment_variables
        .clone()
        .into_iter()
        .map(|envvar| envvar.name.clone())
        .collect();

    let resource_envvar: HashSet<settings::EnvVar> = env_vars
        .iter()
        .filter(|envvar| validation_envvar_with_values_names.contains(&envvar.name))
        .map(|envvar| settings::EnvVar {
            name: envvar.name.clone(),
            value: envvar.value.clone(),
        })
        .collect();

    let resource_envvar_names: HashSet<String> =
        env_vars.iter().map(|envvar| envvar.name.clone()).collect();

    let error_message = match rule.reject {
        settings::Operator::AllAreUsed => {
            if !validation_envvar.is_subset(&resource_envvar)
                || !validation_envvar_names.is_subset(&resource_envvar_names)
            {
                return Ok(());
            }
            let invalid_envvar = validation_envvar
                .intersection(&resource_envvar)
                .map(|envvar| envvar.name.clone())
                .collect::<HashSet<String>>()
                .union(
                    &validation_envvar_names
                        .intersection(&resource_envvar_names)
                        .cloned()
                        .collect(),
                )
                .cloned()
                .collect::<Vec<String>>();

            let invalid_envvar = invalid_envvar.join(", ");
            format!("{} {}", ALL_ARE_USED_ERROR_MSG.to_owned(), invalid_envvar)
        }
        settings::Operator::NotAllAreUsed => {
            if (!resource_envvar.is_empty() && resource_envvar.is_subset(&validation_envvar))
                || (!resource_envvar_names.is_empty()
                    && resource_envvar_names.is_subset(&validation_envvar_names))
            {
                return Ok(());
            }
            let invalid_envvar = validation_envvar
                .difference(&resource_envvar)
                .map(|envvar| envvar.name.clone())
                .collect::<HashSet<String>>()
                .union(
                    &validation_envvar_names
                        .difference(&resource_envvar_names)
                        .cloned()
                        .collect(),
                )
                .cloned()
                .collect::<Vec<String>>();

            let invalid_envvar = invalid_envvar.join(", ");
            format!(
                "{} {}",
                NOT_ALL_ARE_USED_ERROR_MSG.to_owned(),
                invalid_envvar
            )
        }
        settings::Operator::AnyIn => {
            let envvar_names_intersection: HashSet<_> = validation_envvar_names
                .intersection(&resource_envvar_names)
                .cloned()
                .collect();

            let envvar_intersection: HashSet<_> = validation_envvar
                .intersection(&resource_envvar)
                .map(|envvar| envvar.name.clone())
                .collect();

            let invalid_envvar: Vec<String> = envvar_intersection
                .union(&envvar_names_intersection)
                .cloned()
                .collect();

            if invalid_envvar.is_empty() {
                return Ok(());
            }
            let invalid_envvars = invalid_envvar.join(", ");
            format!("{ANY_IN_ERROR_MSG} {invalid_envvars}")
        }
        settings::Operator::AnyNotIn => {
            let envvar_names_intersection: HashSet<_> = validation_envvar_names
                .difference(&resource_envvar_names)
                .cloned()
                .collect();

            let envvar_intersection: HashSet<_> = validation_envvar
                .difference(&resource_envvar)
                .map(|envvar| envvar.name.clone())
                .collect();

            let invalid_envvar: Vec<String> = envvar_intersection
                .union(&envvar_names_intersection)
                .cloned()
                .collect();

            if invalid_envvar.is_empty() {
                return Ok(());
            }
            let invalid_envvars = invalid_envvar.join(", ");
            format!("{ANY_NOT_IN_ERROR_MSG} {invalid_envvars}")
        }
    };
    Err(anyhow!(error_message))
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
    #[case::anyin_succeed_with_no_envvar(
        Rule{
            reject: settings::Operator::AnyIn,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![], None, None)]
    #[case::anyin_fail_all_envvar_is_defined(
        Rule{
            reject: settings::Operator::AnyIn,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar2".to_string(), 
                value: Some("envvar2_value".to_string()),
                ..Default::default()
            },
            apicore::EnvVar{
                name: "envvar3".to_string(), 
                value: Some("aaaaaaaa".to_string()), 
                ..Default::default()
            }],
        Some(ANY_IN_ERROR_MSG.to_owned()),
        Some(vec!["envvar2".to_string(), "envvar3".to_string()]))]
    #[case::anyin_fails_when_an_envvar_with_value_is_defined(
        Rule{
            reject: settings::Operator::AnyIn,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar2".to_string(), 
                value: Some("envvar2_value".to_string()),
                ..Default::default()
            }
        ],
        Some(ANY_IN_ERROR_MSG.to_owned()),
        Some(vec!["envvar2".to_string()]))]
    #[case::anyin_fail_when_envvar_with_name_only_is_defined(
        Rule{
            reject: settings::Operator::AnyIn,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar3".to_string(), 
                value: Some("aaaaaaaa".to_string()), 
                ..Default::default()
            }],
        Some(ANY_IN_ERROR_MSG.to_owned()),
        Some(vec!["envvar3".to_string()]))]
    #[case::anynotin_succeed_all_envvar_defined(
        Rule{
            reject: settings::Operator::AnyNotIn,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar2".to_string(), 
                value: Some("envvar2_value".to_string()),
                ..Default::default()
            },
            apicore::EnvVar{
                name: "envvar3".to_string(), 
                value: Some("aaaaaaaa".to_string()), 
                ..Default::default()
            }],
        None, None)]
    #[case::anynotin_fail_envvar_with_value(
        Rule{
            reject: settings::Operator::AnyNotIn,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar2".to_string(), 
                value: Some("envvar2_value".to_string()),
                ..Default::default()
            },],
        Some(ANY_NOT_IN_ERROR_MSG.to_owned()),
        Some(vec!["envvar3".to_string()]))]
    #[case::anynotin_fail_envvar_name_only(
        Rule{
            reject: settings::Operator::AnyNotIn,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar3".to_string(), 
                value: Some("envvar3_value".to_string()),
                ..Default::default()
            },],
        Some(ANY_NOT_IN_ERROR_MSG.to_owned()),
        Some(vec!["envvar2".to_string()]))]
    #[case::anynotin_fail_no_envvar(
        Rule{
            reject: settings::Operator::AnyNotIn,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![],
        Some(ANY_NOT_IN_ERROR_MSG.to_owned()),
        Some(vec!["envvar2".to_string(), "envvar3".to_string()]))]
    #[case::allareused_fail_all_envvar_are_defined_in_rule(
        Rule{
            reject: settings::Operator::AllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar2".to_string(), 
                value: Some("envvar2_value".to_string()),
                ..Default::default()
            },
            apicore::EnvVar{
                name: "envvar3".to_string(), 
                value: Some("aaaaaaaa".to_string()), 
                ..Default::default()
            }],
        Some(ALL_ARE_USED_ERROR_MSG.to_owned()),
        Some(vec!["envvar2".to_string(), "envvar3".to_string()]))]
    #[case::allareuser_succeed_with_single_envvar_with_name(
        Rule{
            reject: settings::Operator::AllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar3".to_string(), 
                value: Some("aaaaaaaa".to_string()), 
                ..Default::default()
            }],
        None, None)]
    #[case::allareused_succeed_with_single_envvar_with_value(
        Rule{
            reject: settings::Operator::AllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar2".to_string(), 
                value: Some("envvar2_value".to_string()),
                ..Default::default()
            },
        ],
        None, None)]
    #[case::allareused_succeed_with_no_envvar(
        Rule{
            reject: settings::Operator::AllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![ ],
        None, None)]
    #[case::notallareused_all_envvar_should_succeed(
        Rule{
            reject: settings::Operator::NotAllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar2".to_string(), 
                value: Some("envvar2_value".to_string()),
                ..Default::default()
            },
            apicore::EnvVar{
                name: "envvar3".to_string(), 
                value: Some("aaaaaaaa".to_string()), 
                ..Default::default()
        }],
        None, None)]
    #[case::notallareused_missing_only_one_envvar_name_only_should_succeed(
        Rule{
            reject: settings::Operator::NotAllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())},
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar3".to_string(),
                value: Some("aaaaaaaa".to_string()),
                ..Default::default()
            }
        ], None, None)]
    #[case::notallareused_missing_only_one_envvar_with_value_should_succeed(
        Rule{
            reject: settings::Operator::NotAllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![
            apicore::EnvVar{
                name: "envvar2".to_string(), 
                value: Some("envvar2_value".to_string()),
                ..Default::default()
            },
       ], None, None)]
    #[case::notallareused_no_envvar_should_succeed(
        Rule{
            reject: settings::Operator::NotAllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "envvar2".to_string(), value: Some("envvar2_value".to_string())}, 
                settings::EnvVar{name: "envvar3".to_string(), value: None}
            ])},
        vec![ ], Some(NOT_ALL_ARE_USED_ERROR_MSG.to_owned()),
        Some(vec!["envvar2".to_string(), "envvar3".to_string()]))]
    #[case::notallareused_mismatch_envvar(
        Rule{
            reject: settings::Operator::NotAllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "xpto".to_string(), value: Some("bar2".to_string())}, 
            ])},
        vec![
            apicore::EnvVar{
                name: "foo".to_string(), 
                value: Some("bar".to_string()),
                ..Default::default()
            },
       ],
       Some(NOT_ALL_ARE_USED_ERROR_MSG.to_owned()),
       Some(vec!["xpto".to_string()]))]
    #[case::allareused_mismatch_envvar(
        Rule{
            reject: settings::Operator::AllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "xpto".to_string(), value: Some("bar2".to_string())}, 
            ])},
        vec![
            apicore::EnvVar{
                name: "foo".to_string(), 
                value: Some("bar".to_string()),
                ..Default::default()
            },
       ],
       None, None)]
    #[case::anyin_mismatch_envvar(
        Rule{
            reject: settings::Operator::AnyIn,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "xpto".to_string(), value: Some("bar2".to_string())}, 
            ])},
        vec![
            apicore::EnvVar{
                name: "foo".to_string(), 
                value: Some("bar".to_string()),
                ..Default::default()
            },
       ],
       None, None)]
    #[case::anynotin_mismatch_envvar(
        Rule{
            reject: settings::Operator::AnyNotIn,
            environment_variables: HashSet::from([
                settings::EnvVar{name: "xpto".to_string(), value: Some("bar2".to_string())}, 
            ])},
        vec![
            apicore::EnvVar{
                name: "foo".to_string(), 
                value: Some("bar".to_string()),
                ..Default::default()
            },
       ],
       Some(ANY_NOT_IN_ERROR_MSG.to_owned()),
       Some(vec!["xpto".to_string()]))]
    fn rules_test(
        #[case] rule: Rule,
        #[case] container_envvar: Vec<apicore::EnvVar>,
        #[case] error: Option<String>,
        #[case] invalid_envvar: Option<Vec<String>>,
    ) {
        let result = validate_envvar_with_rule(&rule, &container_envvar);
        if let Some(expected_error) = error {
            let err = result.expect_err("Should be an error").to_string();
            assert!(err.contains(&expected_error));
            if let Some(invalid_envvar) = invalid_envvar {
                for envvar in invalid_envvar {
                    assert!(err.contains(&envvar));
                }
            }
        } else {
            result.expect("Should be ok");
        }
    }

    #[test]
    fn podspec_container_envvar_should_be_validated_test() -> Result<(), ()> {
        let podspec = apicore::PodSpec {
            containers: vec![apicore::Container {
                env: Some(vec![apicore::EnvVar {
                    name: "name2".to_string(),
                    value: Some("value2".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            ..Default::default()
        };
        let settings = settings::Settings {
            rules: vec![Rule {
                reject: settings::Operator::AnyIn,
                environment_variables: HashSet::from([
                    settings::EnvVar {
                        name: "envvar".to_string(),
                        value: None,
                    },
                    settings::EnvVar {
                        name: "name2".to_string(),
                        value: Some("value2".to_string()),
                    },
                ]),
                ..Default::default()
            }],
        };
        let result = validate_environment_variables(&podspec, &settings);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("{ANY_IN_ERROR_MSG} name2")
        );
        Ok(())
    }

    #[test]
    fn podspec_init_container_envvar_should_be_validated_test() -> Result<(), ()> {
        let podspec = apicore::PodSpec {
            init_containers: Some(vec![apicore::Container {
                env: Some(vec![apicore::EnvVar {
                    name: "name".to_string(),
                    value: Some("value".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let settings = settings::Settings {
            rules: vec![Rule {
                reject: settings::Operator::AnyIn,
                environment_variables: HashSet::from([
                    settings::EnvVar {
                        name: "envvar".to_string(),
                        value: None,
                    },
                    settings::EnvVar {
                        name: "name".to_string(),
                        value: Some("value".to_string()),
                    },
                ]),
                ..Default::default()
            }],
        };
        let result = validate_environment_variables(&podspec, &settings);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("{ANY_IN_ERROR_MSG} name")
        );
        Ok(())
    }

    #[test]
    fn podspec_ephemeral_container_envvar_should_be_validated_test() -> Result<(), ()> {
        let podspec = apicore::PodSpec {
            ephemeral_containers: Some(vec![apicore::EphemeralContainer {
                env: Some(vec![apicore::EnvVar {
                    name: "name".to_string(),
                    value: Some("value".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let settings = settings::Settings {
            rules: vec![Rule {
                reject: settings::Operator::AnyIn,
                environment_variables: HashSet::from([
                    settings::EnvVar {
                        name: "envvar".to_string(),
                        value: None,
                    },
                    settings::EnvVar {
                        name: "name".to_string(),
                        value: Some("value".to_string()),
                    },
                ]),
                ..Default::default()
            }],
        };
        let result = validate_environment_variables(&podspec, &settings);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("{ANY_IN_ERROR_MSG} name")
        );
        Ok(())
    }
}
