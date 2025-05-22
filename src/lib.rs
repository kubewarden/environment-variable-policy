use std::collections::HashSet;

use anyhow::{anyhow, Error, Result};
use guest::prelude::*;
use k8s_openapi::api::core::v1 as apicore;
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

fn validate_envvar(settings: &Settings, env_vars: &[apicore::EnvVar]) -> Result<()> {
    let resource_env_var_names: HashSet<String> =
        env_vars.iter().map(|envvar| envvar.name.clone()).collect();
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

fn add_container_name_to_error(err: Error, container_name: String) -> Error {
    anyhow!("{}: {}", container_name, err)
}

fn validate_environment_variables(
    pod: &apicore::PodSpec,
    settings: &settings::Settings,
) -> Result<()> {
    let mut results = Vec::<Result<()>>::new();
    for container in pod.containers.iter() {
        if let Some(envvar) = &container.env {
            results.push(
                validate_envvar(settings, envvar)
                    .map_err(|err| add_container_name_to_error(err, container.name.clone())),
            );
        }
    }
    if let Some(init_containers) = &pod.init_containers {
        for container in init_containers.iter() {
            if let Some(envvar) = &container.env {
                results.push(
                    validate_envvar(settings, envvar)
                        .map_err(|err| add_container_name_to_error(err, container.name.clone())),
                );
            }
        }
    }
    if let Some(ephemeral_containers) = &pod.ephemeral_containers {
        for container in ephemeral_containers.iter() {
            if let Some(envvar) = &container.env {
                results.push(
                    validate_envvar(settings, envvar)
                        .map_err(|err| add_container_name_to_error(err, container.name.clone())),
                );
            }
        }
    }
    let errors: Vec<String> = results
        .into_iter()
        .filter_map(|result| result.err())
        .map(|err| err.to_string())
        .collect();
    if !errors.is_empty() {
        return Err(anyhow!(errors.join("\n")));
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

    use crate::{
        CONTAINS_ALL_OF_ERROR_MSG, CONTAINS_ANY_OF_ERROR_MSG, DOES_NOT_CONTAIN_ALL_OF_ERROR_MSG,
        DOES_NOT_CONTAIN_ANY_OF_ERROR_MSG,
    };

    #[rstest]
    #[case::contains_any_of(Settings::ContainsAnyOf{envvars: HashSet::from(["a".to_owned(), "b".to_owned()])}, vec!["c".to_owned()], CONTAINS_ANY_OF_ERROR_MSG)]
    #[case::does_not_contain_any_of(Settings::DoesNotContainAnyOf{envvars: HashSet::from(["a".to_owned(), "b".to_owned()])}, vec!["b".to_owned(), "c".to_owned()],  DOES_NOT_CONTAIN_ANY_OF_ERROR_MSG)]
    #[case::contains_all_of(Settings::ContainsAllOf{envvars: HashSet::from(["a".to_owned(), "b".to_owned()])}, vec!["a".to_owned(), "c".to_owned()], CONTAINS_ALL_OF_ERROR_MSG)]
    #[case::does_not_contains_all_of(Settings::DoesNotContainAllOf{envvars: HashSet::from(["a".to_owned(), "b".to_owned()])}, vec!["a".to_owned(), "b".to_owned()], DOES_NOT_CONTAIN_ALL_OF_ERROR_MSG)]
    fn test_multiple_container_validation(
        #[case] settings: Settings,
        #[case] envvars: Vec<String>,
        #[case] error_message: &str,
    ) {
        let container_envvar = Some(
            envvars
                .iter()
                .map(|name| apicore::EnvVar {
                    name: name.clone(),
                    ..Default::default()
                })
                .collect::<Vec<_>>(),
        );

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

        // This test exists to ensure that we will not allow validation of multiple rules at the same time.
        let error = validate_environment_variables(pod_spec, &settings)
            .expect_err("Expected validation to fail");
        println!("{}", error);
        // ensure that all container with invalid environment variables are listed in the error
        // message
        for c in 1..6 {
            assert!(
                error
                    .to_string()
                    .contains(format!("test-container{}: {}", c, error_message).as_str()),
                "Validation error message does not contain expected text"
            );
        }
    }
}
