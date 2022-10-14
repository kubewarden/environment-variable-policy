use std::collections::HashSet;

use anyhow::{anyhow, Result};
use guest::prelude::*;
use k8s_openapi::api::core::v1 as apicore;
use kubewarden_policy_sdk::wapc_guest as guest;
extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use crate::settings::Rule;

const ALL_ARE_USED_ERROR_MSG: &str = "Rule environment variables are not defined in the resource.";
const NOT_ALL_ARE_USED_ERROR_MSG: &str = "Rule environment variables are defined in the resource.";
const ANY_IN_ERROR_MSG: &str = "Resource misses at least one environment variable from the rule.";
const ANY_NOT_IN_ERROR_MSG: &str =
    "Resource should not contain any environment variable from the rule.";

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<settings::Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate_envvar_with_rule(rule: &Rule, env_vars: &Vec<apicore::EnvVar>) -> Result<()> {
    let error_message: &str;
    let mut resource_env_var: HashSet<settings::EnvVar> = HashSet::new();
    for envvar in env_vars {
        resource_env_var.insert(settings::EnvVar {
            name: envvar.name.clone(),
            value: envvar.value.clone(),
        });
    }
    match rule.reject {
        settings::Operator::AllAreUsed => {
            if !rule.environment_variables.is_subset(&resource_env_var) {
                return Ok(());
            } else {
                error_message = ALL_ARE_USED_ERROR_MSG
            }
        }
        settings::Operator::NotAllAreUsed => {
            let difference: HashSet<_> = rule
                .environment_variables
                .difference(&resource_env_var)
                .collect();
            if difference.is_empty() {
                return Ok(());
            } else {
                error_message = NOT_ALL_ARE_USED_ERROR_MSG
            }
        }
        settings::Operator::AnyIn => {
            let intersection: HashSet<_> = rule
                .environment_variables
                .intersection(&resource_env_var)
                .collect();
            if intersection.is_empty() {
                return Ok(());
            } else {
                error_message = ANY_IN_ERROR_MSG
            }
        }
        settings::Operator::AnyNotIn => {
            let intersection: HashSet<_> = rule
                .environment_variables
                .difference(&resource_env_var)
                .collect();
            if intersection.is_empty() {
                return Ok(());
            } else {
                error_message = ANY_NOT_IN_ERROR_MSG
            }
        }
    }
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
    use std::collections::HashSet;

    #[test]
    fn allareused_operator_ensure_all_envvar_are_defined_in_the_rule() -> Result<(), ()> {
        let rule = Rule {
            reject: settings::Operator::AllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar {
                    name: "name".to_string(),
                    value: Some("value".to_string()),
                },
                settings::EnvVar {
                    name: "name3".to_string(),
                    value: Some("value3".to_string()),
                },
            ]),
        };
        let envvar = vec![
            apicore::EnvVar {
                name: "name".to_string(),
                value: Some("value".to_string()),
                ..Default::default()
            },
            apicore::EnvVar {
                name: "name2".to_string(),
                value: Some("value2".to_string()),
                ..Default::default()
            },
        ];
        let result = validate_envvar_with_rule(&rule, &envvar);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn allareused_should_reject_if_envvar_is_not_in_the_resource() -> Result<(), ()> {
        let rule = Rule {
            reject: settings::Operator::AllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar {
                    name: "name2".to_string(),
                    value: Some("value2".to_string()),
                },
                settings::EnvVar {
                    name: "name3".to_string(),
                    value: Some("value3".to_string()),
                },
            ]),
        };
        let envvar = vec![
            apicore::EnvVar {
                name: "name2".to_string(),
                value: Some("value2".to_string()),
                ..Default::default()
            },
            apicore::EnvVar {
                name: "name3".to_string(),
                value: Some("value3".to_string()),
                ..Default::default()
            },
        ];
        let result = validate_envvar_with_rule(&rule, &envvar);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ALL_ARE_USED_ERROR_MSG);
        Ok(())
    }

    #[test]
    fn notallareused_should_fail_when_envvar_is_not_defined_in_the_resource() -> Result<(), ()> {
        let rule = Rule {
            reject: settings::Operator::NotAllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar {
                    name: "name".to_string(),
                    value: Some("value".to_string()),
                },
                settings::EnvVar {
                    name: "name3".to_string(),
                    value: Some("value3".to_string()),
                },
            ]),
        };
        let envvar = vec![
            apicore::EnvVar {
                name: "name".to_string(),
                value: Some("value".to_string()),
                ..Default::default()
            },
            apicore::EnvVar {
                name: "name2".to_string(),
                value: Some("value2".to_string()),
                ..Default::default()
            },
        ];
        let result = validate_envvar_with_rule(&rule, &envvar);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), NOT_ALL_ARE_USED_ERROR_MSG);
        Ok(())
    }

    #[test]
    fn notallareused_should_successed_when_envvar_is_defined_in_the_resource() -> Result<(), ()> {
        let rule = Rule {
            reject: settings::Operator::NotAllAreUsed,
            environment_variables: HashSet::from([
                settings::EnvVar {
                    name: "name".to_string(),
                    value: Some("value".to_string()),
                },
                settings::EnvVar {
                    name: "name3".to_string(),
                    value: Some("value3".to_string()),
                },
            ]),
        };
        let envvar = vec![
            apicore::EnvVar {
                name: "name".to_string(),
                value: Some("value".to_string()),
                ..Default::default()
            },
            apicore::EnvVar {
                name: "name3".to_string(),
                value: Some("value3".to_string()),
                ..Default::default()
            },
        ];
        let result = validate_envvar_with_rule(&rule, &envvar);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn anyin_should_succed_when_none_envvar_is_defined_in_the_resource() -> Result<(), ()> {
        let rule = Rule {
            reject: settings::Operator::AnyIn,
            environment_variables: HashSet::from([
                settings::EnvVar {
                    name: "name".to_string(),
                    value: Some("value".to_string()),
                },
                settings::EnvVar {
                    name: "name2".to_string(),
                    value: Some("value2".to_string()),
                },
            ]),
        };
        let envvar = vec![
            apicore::EnvVar {
                name: "name3".to_string(),
                value: Some("value3".to_string()),
                ..Default::default()
            },
            apicore::EnvVar {
                name: "name4".to_string(),
                value: Some("value4".to_string()),
                ..Default::default()
            },
        ];
        let result = validate_envvar_with_rule(&rule, &envvar);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn anyin_should_reject_if_some_envvar_is_defined_in_the_resource() -> Result<(), ()> {
        let rule = Rule {
            reject: settings::Operator::AnyIn,
            environment_variables: HashSet::from([
                settings::EnvVar {
                    name: "name".to_string(),
                    value: Some("value".to_string()),
                },
                settings::EnvVar {
                    name: "name2".to_string(),
                    value: Some("value2".to_string()),
                },
            ]),
        };
        let envvar = vec![
            apicore::EnvVar {
                name: "name3".to_string(),
                value: Some("value3".to_string()),
                ..Default::default()
            },
            apicore::EnvVar {
                name: "name2".to_string(),
                value: Some("value2".to_string()),
                ..Default::default()
            },
        ];
        let result = validate_envvar_with_rule(&rule, &envvar);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);
        Ok(())
    }

    #[test]
    fn anynotin_should_succed_when_none_envvar_is_defined_in_the_resource() -> Result<(), ()> {
        let rule = Rule {
            reject: settings::Operator::AnyNotIn,
            environment_variables: HashSet::from([
                settings::EnvVar {
                    name: "name3".to_string(),
                    value: Some("value3".to_string()),
                },
                settings::EnvVar {
                    name: "name4".to_string(),
                    value: Some("value4".to_string()),
                },
            ]),
        };
        let envvar = vec![
            apicore::EnvVar {
                name: "name3".to_string(),
                value: Some("value3".to_string()),
                ..Default::default()
            },
            apicore::EnvVar {
                name: "name4".to_string(),
                value: Some("value4".to_string()),
                ..Default::default()
            },
        ];
        let result = validate_envvar_with_rule(&rule, &envvar);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn anynotin_should_reject_if_some_envvar_is_defined_in_the_resource() -> Result<(), ()> {
        let rule = Rule {
            reject: settings::Operator::AnyNotIn,
            environment_variables: HashSet::from([
                settings::EnvVar {
                    name: "name".to_string(),
                    value: Some("value".to_string()),
                },
                settings::EnvVar {
                    name: "name2".to_string(),
                    value: Some("value2".to_string()),
                },
            ]),
        };
        let envvar = vec![
            apicore::EnvVar {
                name: "name2".to_string(),
                value: Some("value2".to_string()),
                ..Default::default()
            },
            apicore::EnvVar {
                name: "name4".to_string(),
                value: Some("value4".to_string()),
                ..Default::default()
            },
        ];
        let result = validate_envvar_with_rule(&rule, &envvar);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ANY_NOT_IN_ERROR_MSG);
        Ok(())
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
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);
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
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);
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
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);
        Ok(())
    }
}
