use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use guest::prelude::*;
use k8s_openapi::api::core::v1::{self as apicore, Container, EphemeralContainer};
use kubewarden_policy_sdk::wapc_guest as guest;
extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{protocol_version_guest, request::ValidationRequest, validate_settings};
use operators::*;
use settings::Settings;

mod operators;
mod settings;

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<settings::Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate_envvar(settings: &Settings, env_vars: &[String]) -> Result<()> {
    let resource_env_var_names: HashSet<String> = env_vars.iter().cloned().collect();
    match settings {
        Settings::ContainsAllOf { envvars } => contains_all_of(envvars, &resource_env_var_names),
        Settings::DoesNotContainAllOf { envvars } => {
            does_not_contain_all_of(envvars, &resource_env_var_names)
        }
        Settings::ContainsAnyOf { envvars } => contains_any_of(envvars, &resource_env_var_names),
        Settings::DoesNotContainAnyOf { envvars } => {
            does_not_contain_any_of(envvars, &resource_env_var_names)
        }
    }
}

fn get_containers_env_vars(containers: &[Container]) -> HashMap<String, Vec<String>> {
    let mut results = HashMap::new();
    for container in containers {
        if let Some(envvar) = &container.env {
            results.insert(
                container.name.clone(),
                envvar.iter().map(|e| e.name.clone()).collect(),
            );
        }
    }
    results
}

fn get_ephemeral_containers_env_vars(
    containers: &[EphemeralContainer],
) -> HashMap<String, Vec<String>> {
    let mut results = HashMap::new();
    for container in containers {
        if let Some(envvar) = &container.env {
            results.insert(
                container.name.clone(),
                envvar.iter().map(|e| e.name.clone()).collect(),
            );
        }
    }
    results
}

fn validate_environment_variables(
    pod: &apicore::PodSpec,
    settings: &settings::Settings,
) -> Result<(), Vec<String>> {
    let mut envvars = get_containers_env_vars(&pod.containers);
    envvars.extend(get_containers_env_vars(
        pod.init_containers.as_ref().unwrap_or(&vec![]),
    ));
    envvars.extend(get_ephemeral_containers_env_vars(
        pod.ephemeral_containers.as_ref().unwrap_or(&vec![]),
    ));
    let errors = envvars
        .iter()
        .filter_map(|(container_name, envvar)| {
            validate_envvar(settings, envvar)
                .map_err(|err| anyhow!("{}: {}", container_name, err))
                .err()
        })
        .map(|err| err.to_string())
        .collect::<Vec<_>>();

    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(())
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<settings::Settings> =
        ValidationRequest::new(payload)?;
    let pod_spec = validation_request.extract_pod_spec_from_object()?;
    if let Err(errors) =
        validate_environment_variables(&pod_spec.unwrap_or_default(), &validation_request.settings)
    {
        return kubewarden::reject_request(Some(errors.join(", ")), None, None, None);
    }
    kubewarden::accept_request()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::CONTAINS_ANY_OF_ERROR_MSG;

    #[test]
    fn test_envvar_extraction() {
        let envvars = ["a".to_owned(), "c".to_owned()];
        let container_envvar = Some(
            envvars
                .iter()
                .map(|name| apicore::EnvVar {
                    name: name.clone(),
                    ..Default::default()
                })
                .collect::<Vec<_>>(),
        );

        let containers = vec![
            apicore::Container {
                name: "test-container1".to_string(),
                env: container_envvar.clone(),
                ..Default::default()
            },
            apicore::Container {
                name: "test-container2".to_string(),
                env: container_envvar.clone(),
                ..Default::default()
            },
        ];
        let ephemeral_containers = vec![
            apicore::EphemeralContainer {
                name: "test-container1".to_string(),
                env: container_envvar.clone(),
                ..Default::default()
            },
            apicore::EphemeralContainer {
                name: "test-container2".to_string(),
                env: container_envvar.clone(),
                ..Default::default()
            },
        ];
        let mut result = get_containers_env_vars(&containers);
        assert_eq!(result.get("test-container1").unwrap(), &envvars.to_vec());
        assert_eq!(result.get("test-container2").unwrap(), &envvars.to_vec());
        assert_eq!(result.len(), 2);
        result = get_ephemeral_containers_env_vars(&ephemeral_containers);
        assert_eq!(result.get("test-container1").unwrap(), &envvars.to_vec());
        assert_eq!(result.get("test-container2").unwrap(), &envvars.to_vec());
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_multiple_container_error_message() {
        let settings = Settings::ContainsAnyOf {
            envvars: HashSet::from(["a".to_owned(), "b".to_owned()]),
        };
        let container_envvar = Some(Vec::from([apicore::EnvVar {
            name: "c".to_owned(),
            ..Default::default()
        }]));

        let pod_spec = &apicore::PodSpec {
            containers: vec![
                apicore::Container {
                    name: "test-container1".to_string(),
                    env: container_envvar.clone(),
                    ..Default::default()
                },
                apicore::Container {
                    name: "test-container2".to_string(),
                    env: container_envvar.clone(),
                    ..Default::default()
                },
            ],
            init_containers: Some(vec![
                apicore::Container {
                    name: "test-container3".to_string(),
                    env: container_envvar.clone(),
                    ..Default::default()
                },
                apicore::Container {
                    name: "test-container4".to_string(),
                    env: container_envvar.clone(),
                    ..Default::default()
                },
            ]),
            ephemeral_containers: Some(vec![
                apicore::EphemeralContainer {
                    name: "test-container5".to_string(),
                    env: container_envvar.clone(),
                    ..Default::default()
                },
                apicore::EphemeralContainer {
                    name: "test-container6".to_string(),
                    env: container_envvar.clone(),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };

        // Ensure that all problematic containers are caught and there is an error for each
        let errors = validate_environment_variables(pod_spec, &settings)
            .expect_err("Expected validation to fail");
        assert_eq!(errors.len(), 6, "Expected 6 errors, got {}", errors.len());
        for c in 1..6 {
            assert!(
                errors.iter().any(|errmsg| errmsg.starts_with(&format!(
                    "test-container{}: {} ",
                    c, CONTAINS_ANY_OF_ERROR_MSG
                ))),
                "Validation error message does not contain expected text"
            );
        }
    }
}
