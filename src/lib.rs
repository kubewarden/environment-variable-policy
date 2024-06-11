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
    "Resource cannot have all the environment variables from the rule defined.";
const NOT_ALL_ARE_USED_ERROR_MSG: &str =
    "Resource should have all the environment variables from the rule defined. Invalid environment variables found:";
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
    let error_message: String;
    let resource_env_var: HashSet<settings::EnvVar> = env_vars
        .iter()
        .map(|envvar| settings::EnvVar {
            name: envvar.name.clone(),
            value: envvar.value.clone(),
        })
        .collect();
    let resource_env_var_names: HashSet<settings::EnvVar> = env_vars
        .iter()
        .map(|envvar| settings::EnvVar {
            name: envvar.name.clone(),
            value: None,
        })
        .collect();
    let validation_envvar_with_values: HashSet<settings::EnvVar> = rule
        .environment_variables
        .clone()
        .into_iter()
        .filter(|envvar| envvar.value.is_some())
        .collect();
    let validation_envvar_name_only: HashSet<settings::EnvVar> = rule
        .environment_variables
        .clone()
        .into_iter()
        .filter(|envvar| envvar.value.is_none())
        .collect();
    match rule.reject {
        settings::Operator::AllAreUsed => {
            if !validation_envvar_with_values.is_subset(&resource_env_var)
                || !validation_envvar_name_only.is_subset(&resource_env_var_names)
            {
                return Ok(());
            } else {
                error_message = ALL_ARE_USED_ERROR_MSG.to_owned()
            }
        }
        settings::Operator::NotAllAreUsed => {
            let difference: HashSet<_> = validation_envvar_with_values
                .difference(&resource_env_var)
                .collect();
            let difference_names_only: HashSet<_> = validation_envvar_name_only
                .difference(&resource_env_var_names)
                .collect();
            if difference.is_empty() && difference_names_only.is_empty() {
                return Ok(());
            } else {
                let invalid_envvars = difference
                    .union(&difference_names_only)
                    .map(|envvar| envvar.name.clone())
                    .collect::<Vec<String>>()
                    .join(", ");
                error_message = format!("{NOT_ALL_ARE_USED_ERROR_MSG} {invalid_envvars}");
            }
        }
        settings::Operator::AnyIn => {
            let name_value_intersection: HashSet<_> = validation_envvar_with_values
                .intersection(&resource_env_var)
                .collect();
            let name_intersection: HashSet<_> = validation_envvar_name_only
                .intersection(&resource_env_var_names)
                .collect();
            if name_value_intersection.is_empty() && name_intersection.is_empty() {
                return Ok(());
            } else {
                let invalid_envvars = name_value_intersection
                    .union(&name_intersection)
                    .map(|envvar| envvar.name.clone())
                    .collect::<Vec<String>>()
                    .join(", ");
                error_message = format!("{ANY_IN_ERROR_MSG} {invalid_envvars}");
            }
        }
        settings::Operator::AnyNotIn => {
            let intersection: HashSet<_> = validation_envvar_with_values
                .difference(&resource_env_var)
                .collect();
            let intersection_name: HashSet<_> = validation_envvar_name_only
                .difference(&resource_env_var_names)
                .collect();
            println!("{:?}", intersection);
            println!("{:?}", intersection_name);
            if intersection.is_empty() && intersection_name.is_empty() {
                return Ok(());
            } else {
                let invalid_envvars = intersection
                    .union(&intersection_name)
                    .map(|envvar| envvar.name.clone())
                    .collect::<Vec<String>>()
                    .join(", ");
                error_message = format!("{ANY_NOT_IN_ERROR_MSG} {invalid_envvars}");
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
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("{NOT_ALL_ARE_USED_ERROR_MSG} name3")
        );
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
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("{ANY_IN_ERROR_MSG} name2")
        );
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
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("{ANY_NOT_IN_ERROR_MSG} name")
        );
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
