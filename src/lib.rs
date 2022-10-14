use regex::Regex;
use std::collections::HashSet;

use anyhow::{anyhow, Result};
use guest::prelude::*;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::CronJob;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1 as apicore;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::core::v1::ReplicationController;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::Resource;
use kubewarden_policy_sdk::wapc_guest as guest;
use lazy_static::lazy_static;
extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{
    protocol_version_guest, request::KubernetesAdmissionRequest, request::ValidationRequest,
    validate_settings,
};

mod settings;
use crate::settings::Rule;

static ALL_ARE_USED_ERROR_MSG: &str = "Rule environment variables are not defined in the resource.";
static NOT_ALL_ARE_USED_ERROR_MSG: &str = "Rule environment variables are defined in the resource.";
static ANY_IN_ERROR_MSG: &str = "Resource misses at least one environment variable from the rule.";
static ANY_NOT_IN_ERROR_MSG: &str =
    "Resource should not contain any environment variable from the rule.";

static EXTRACT_LABEL_ANNOTATION_REGEX_STR: &str = r#"\[['"](.*)['"]\]"#;
lazy_static! {
    static ref EXTRACT_LABEL_ANNOTATION_REGEX: Regex =
        Regex::new(EXTRACT_LABEL_ANNOTATION_REGEX_STR).unwrap();
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<settings::Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate_envvar_with_rule(
    rule: &Rule,
    pod: &apicore::PodSpec,
    metadata: &ObjectMeta,
    env_vars: &Vec<apicore::EnvVar>,
) -> Result<()> {
    let error_message: &str;
    let mut resource_env_var: HashSet<settings::EnvVar> = HashSet::new();
    for envvar in env_vars {
        if let Some(env_var_source) = &envvar.value_from {
            if let Some(field_ref) = &env_var_source.field_ref {
                let mut envvar_value = None;
                let field_path = field_ref.field_path.as_str();
                if field_path == "metadata.name" {
                    envvar_value = metadata.name.clone();
                } else if field_path == "metadata.namespace" {
                    envvar_value = metadata.namespace.clone();
                } else if field_path.starts_with("metadata.labels") {
                    if let Some(labels) = &metadata.labels {
                        let label = EXTRACT_LABEL_ANNOTATION_REGEX
                            .captures(field_path)
                            .unwrap()
                            .get(1)
                            .unwrap()
                            .as_str();
                        envvar_value = labels.get(label).cloned();
                    } else {
                        envvar_value = None;
                    }
                } else if field_path.starts_with("metadata.annotations") {
                    if let Some(annotations) = &metadata.annotations {
                        let annotation = EXTRACT_LABEL_ANNOTATION_REGEX
                            .captures(field_path)
                            .unwrap()
                            .get(1)
                            .unwrap()
                            .as_str();
                        envvar_value = annotations.get(annotation).cloned()
                    } else {
                        envvar_value = None;
                    }
                } else if field_path == "spec.nodeName" {
                    envvar_value = pod.node_name.clone();
                } else if field_path == "spec.serviceAccountName" {
                    envvar_value = pod.service_account_name.clone();
                }
                resource_env_var.insert(settings::EnvVar {
                    name: envvar.name.clone(),
                    value: envvar_value,
                });
            }
        } else {
            resource_env_var.insert(settings::EnvVar {
                name: envvar.name.clone(),
                value: envvar.value.clone(),
            });
        }
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
    metadata: &ObjectMeta,
    settings: &settings::Settings,
) -> Result<()> {
    for container in pod.containers.iter() {
        for rule in settings.rules.iter() {
            if let Some(envvar) = &container.env {
                validate_envvar_with_rule(rule, pod, metadata, envvar)?;
            }
        }
    }
    if let Some(init_containers) = &pod.init_containers {
        for container in init_containers.iter() {
            for rule in settings.rules.iter() {
                if let Some(envvar) = &container.env {
                    validate_envvar_with_rule(rule, pod, metadata, envvar)?;
                }
            }
        }
    }
    if let Some(ephemeral_containers) = &pod.ephemeral_containers {
        for container in ephemeral_containers.iter() {
            for rule in settings.rules.iter() {
                if let Some(envvar) = &container.env {
                    validate_envvar_with_rule(rule, pod, metadata, envvar)?;
                }
            }
        }
    }
    Ok(())
}
pub fn extract_metadata_from_object(request: &KubernetesAdmissionRequest) -> Result<ObjectMeta> {
    match request.kind.kind.as_str() {
        Deployment::KIND => {
            let deployment = serde_json::from_value::<Deployment>(request.object.clone())?;
            Ok(deployment.metadata)
        },
        ReplicaSet::KIND => {
            let replicaset = serde_json::from_value::<ReplicaSet>(request.object.clone())?;
            Ok(replicaset.metadata)
        },
        StatefulSet::KIND => {
            let statefulset = serde_json::from_value::<StatefulSet>(request.object.clone())?;
            Ok(statefulset.metadata)
        },
        DaemonSet::KIND => {
            let daemonset = serde_json::from_value::<DaemonSet>(request.object.clone())?;
            Ok(daemonset.metadata)
        },
        ReplicationController::KIND => {
            let replication_controller = serde_json::from_value::<ReplicationController>(request.object.clone())?;
            Ok(replication_controller.metadata)
        },
        CronJob::KIND => {
            let cronjob = serde_json::from_value::<CronJob>(request.object.clone())?;
            Ok(cronjob.metadata)
        },
        Job::KIND => {
            let job = serde_json::from_value::<Job>(request.object.clone())?;
            Ok(job.metadata)
        },
        Pod::KIND => {
            let pod = serde_json::from_value::<Pod>(request.object.clone())?;
            Ok(pod.metadata)
        },
        _ => {
            Err(anyhow!("Object should be one of these kinds: Deployment, ReplicaSet, StatefulSet, DaemonSet, ReplicationController, Job, CronJob, Pod"))
        }
    }
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<settings::Settings> =
        ValidationRequest::new(payload)?;
    match validation_request.extract_pod_spec_from_object() {
        Ok(pod_spec) => {
            if let Some(pod_spec) = pod_spec {
                let metadata = extract_metadata_from_object(&validation_request.request)?;
                return match validate_environment_variables(
                    &pod_spec,
                    &metadata,
                    &validation_request.settings,
                ) {
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
    use std::collections::BTreeMap;
    use std::collections::HashSet;

    use k8s_openapi::api::core::v1::EnvVarSource;
    use k8s_openapi::api::core::v1::ObjectFieldSelector;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    use kubewarden_policy_sdk::request::GroupVersionKind;

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
        let metadata = ObjectMeta {
            name: Some("value2".to_string()),
            ..Default::default()
        };
        let podspec = apicore::PodSpec {
            ..Default::default()
        };
        let result = validate_envvar_with_rule(&rule, &podspec, &metadata, &envvar);
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
        let metadata = ObjectMeta {
            name: Some("value2".to_string()),
            ..Default::default()
        };
        let podspec = apicore::PodSpec {
            ..Default::default()
        };
        let result = validate_envvar_with_rule(&rule, &podspec, &metadata, &envvar);
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
        let metadata = ObjectMeta {
            name: Some("value2".to_string()),
            ..Default::default()
        };
        let podspec = apicore::PodSpec {
            ..Default::default()
        };
        let result = validate_envvar_with_rule(&rule, &podspec, &metadata, &envvar);
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
        let metadata = ObjectMeta {
            name: Some("value2".to_string()),
            ..Default::default()
        };
        let podspec = apicore::PodSpec {
            ..Default::default()
        };
        let result = validate_envvar_with_rule(&rule, &podspec, &metadata, &envvar);
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
        let metadata = ObjectMeta {
            name: Some("value2".to_string()),
            ..Default::default()
        };
        let podspec = apicore::PodSpec {
            ..Default::default()
        };
        let result = validate_envvar_with_rule(&rule, &podspec, &metadata, &envvar);
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
        let metadata = ObjectMeta {
            name: Some("value2".to_string()),
            ..Default::default()
        };
        let podspec = apicore::PodSpec {
            ..Default::default()
        };
        let result = validate_envvar_with_rule(&rule, &podspec, &metadata, &envvar);
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
        let metadata = ObjectMeta {
            name: Some("value2".to_string()),
            ..Default::default()
        };
        let podspec = apicore::PodSpec {
            ..Default::default()
        };
        let result = validate_envvar_with_rule(&rule, &podspec, &metadata, &envvar);
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
        let metadata = ObjectMeta {
            name: Some("value2".to_string()),
            ..Default::default()
        };
        let podspec = apicore::PodSpec {
            ..Default::default()
        };
        let result = validate_envvar_with_rule(&rule, &podspec, &metadata, &envvar);
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
        let metadata = ObjectMeta {
            name: Some("mypod".to_string()),
            ..Default::default()
        };
        let result = validate_environment_variables(&podspec, &metadata, &settings);
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
        let metadata = ObjectMeta {
            name: Some("mypod".to_string()),
            ..Default::default()
        };
        let result = validate_environment_variables(&podspec, &metadata, &settings);
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
        let metadata = ObjectMeta {
            name: Some("mypod".to_string()),
            ..Default::default()
        };
        let result = validate_environment_variables(&podspec, &metadata, &settings);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);
        Ok(())
    }

    #[test]
    fn extract_metadata_from_deployment_test() -> Result<(), ()> {
        let metadata = ObjectMeta {
            name: Some("mypod".to_string()),
            ..Default::default()
        };
        let deployment = Deployment {
            metadata: metadata.clone(),
            ..Default::default()
        };
        let request = KubernetesAdmissionRequest {
            object: serde_json::to_value(deployment).unwrap(),
            kind: GroupVersionKind {
                kind: Deployment::KIND.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let meta = extract_metadata_from_object(&request);
        assert_eq!(meta.ok().unwrap(), metadata);
        Ok(())
    }

    #[test]
    fn extract_metadata_from_replicaset_test() -> Result<(), ()> {
        let metadata = ObjectMeta {
            name: Some("mypod".to_string()),
            ..Default::default()
        };
        let replicaset = ReplicaSet {
            metadata: metadata.clone(),
            ..Default::default()
        };
        let request = KubernetesAdmissionRequest {
            object: serde_json::to_value(replicaset).unwrap(),
            kind: GroupVersionKind {
                kind: ReplicaSet::KIND.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let meta = extract_metadata_from_object(&request);
        assert_eq!(meta.ok().unwrap(), metadata);
        Ok(())
    }

    #[test]
    fn extract_metadata_from_statefulset_test() -> Result<(), ()> {
        let metadata = ObjectMeta {
            name: Some("mypod".to_string()),
            ..Default::default()
        };
        let statefulset = StatefulSet {
            metadata: metadata.clone(),
            ..Default::default()
        };
        let request = KubernetesAdmissionRequest {
            object: serde_json::to_value(statefulset).unwrap(),
            kind: GroupVersionKind {
                kind: StatefulSet::KIND.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let meta = extract_metadata_from_object(&request);
        assert_eq!(meta.ok().unwrap(), metadata);
        Ok(())
    }

    #[test]
    fn extract_metadata_from_daemonset_test() -> Result<(), ()> {
        let metadata = ObjectMeta {
            name: Some("mypod".to_string()),
            ..Default::default()
        };
        let daemonset = DaemonSet {
            metadata: metadata.clone(),
            ..Default::default()
        };
        let request = KubernetesAdmissionRequest {
            object: serde_json::to_value(daemonset).unwrap(),
            kind: GroupVersionKind {
                kind: DaemonSet::KIND.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let meta = extract_metadata_from_object(&request);
        assert_eq!(meta.ok().unwrap(), metadata);
        Ok(())
    }

    #[test]
    fn extract_metadata_from_replicationcontroller_test() -> Result<(), ()> {
        let metadata = ObjectMeta {
            name: Some("mypod".to_string()),
            ..Default::default()
        };
        let replication_controller = ReplicationController {
            metadata: metadata.clone(),
            ..Default::default()
        };
        let request = KubernetesAdmissionRequest {
            object: serde_json::to_value(replication_controller).unwrap(),
            kind: GroupVersionKind {
                kind: ReplicationController::KIND.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let meta = extract_metadata_from_object(&request);
        assert_eq!(meta.ok().unwrap(), metadata);
        Ok(())
    }

    #[test]
    fn extract_metadata_from_cronjob_test() -> Result<(), ()> {
        let metadata = ObjectMeta {
            name: Some("mypod".to_string()),
            ..Default::default()
        };
        let cronjob = CronJob {
            metadata: metadata.clone(),
            ..Default::default()
        };
        let request = KubernetesAdmissionRequest {
            object: serde_json::to_value(cronjob).unwrap(),
            kind: GroupVersionKind {
                kind: CronJob::KIND.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let meta = extract_metadata_from_object(&request);
        assert_eq!(meta.ok().unwrap(), metadata);
        Ok(())
    }

    #[test]
    fn extract_metadata_from_job_test() -> Result<(), ()> {
        let metadata = ObjectMeta {
            name: Some("mypod".to_string()),
            ..Default::default()
        };
        let job = Job {
            metadata: metadata.clone(),
            ..Default::default()
        };
        let request = KubernetesAdmissionRequest {
            object: serde_json::to_value(job).unwrap(),
            kind: GroupVersionKind {
                kind: Job::KIND.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let meta = extract_metadata_from_object(&request);
        assert_eq!(meta.ok().unwrap(), metadata);
        Ok(())
    }

    #[test]
    fn policy_should_validate_envvar_with_valuefrom_namespace_test() -> Result<(), ()> {
        let podspec = apicore::PodSpec {
            containers: vec![apicore::Container {
                env: Some(vec![apicore::EnvVar {
                    name: "name2".to_string(),
                    value_from: Some(EnvVarSource {
                        field_ref: Some(ObjectFieldSelector {
                            field_path: "metadata.namespace".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
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
        let metadata = ObjectMeta {
            namespace: Some("value2".to_string()),
            ..Default::default()
        };
        let result = validate_environment_variables(&podspec, &metadata, &settings);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);
        Ok(())
    }

    #[test]
    fn policy_should_validate_envvar_with_valuefrom_name_test() -> Result<(), ()> {
        let podspec = apicore::PodSpec {
            containers: vec![apicore::Container {
                env: Some(vec![apicore::EnvVar {
                    name: "name2".to_string(),
                    value_from: Some(EnvVarSource {
                        field_ref: Some(ObjectFieldSelector {
                            field_path: "metadata.name".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
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
        let metadata = ObjectMeta {
            name: Some("value2".to_string()),
            ..Default::default()
        };
        let result = validate_environment_variables(&podspec, &metadata, &settings);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);
        Ok(())
    }

    #[test]
    fn policy_should_validate_envvar_with_valuefrom_labels_test() -> Result<(), ()> {
        let podspec = apicore::PodSpec {
            containers: vec![apicore::Container {
                env: Some(vec![apicore::EnvVar {
                    name: "name2".to_string(),
                    value_from: Some(EnvVarSource {
                        field_ref: Some(ObjectFieldSelector {
                            field_path: "metadata.labels['test']".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
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
        let metadata = ObjectMeta {
            labels: Some(BTreeMap::from([("test".to_string(), "value2".to_string())])),
            ..Default::default()
        };
        let result = validate_environment_variables(&podspec, &metadata, &settings);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);

        let podspec = apicore::PodSpec {
            containers: vec![apicore::Container {
                env: Some(vec![apicore::EnvVar {
                    name: "name2".to_string(),
                    value_from: Some(EnvVarSource {
                        field_ref: Some(ObjectFieldSelector {
                            field_path: "metadata.labels[\"test\"]".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            ..Default::default()
        };

        let result = validate_environment_variables(&podspec, &metadata, &settings);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);

        Ok(())
    }

    #[test]
    fn policy_should_validate_envvar_with_valuefrom_annotations_test() -> Result<(), ()> {
        let podspec = apicore::PodSpec {
            containers: vec![apicore::Container {
                env: Some(vec![apicore::EnvVar {
                    name: "name2".to_string(),
                    value_from: Some(EnvVarSource {
                        field_ref: Some(ObjectFieldSelector {
                            field_path: "metadata.annotations['test']".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
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
        let metadata = ObjectMeta {
            annotations: Some(BTreeMap::from([("test".to_string(), "value2".to_string())])),
            ..Default::default()
        };
        let result = validate_environment_variables(&podspec, &metadata, &settings);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);
        Ok(())
    }

    #[test]
    fn policy_should_validate_envvar_with_valuefrom_node_name_test() -> Result<(), ()> {
        let podspec = apicore::PodSpec {
            node_name: Some("value2".to_string()),
            containers: vec![apicore::Container {
                env: Some(vec![apicore::EnvVar {
                    name: "name2".to_string(),
                    value_from: Some(EnvVarSource {
                        field_ref: Some(ObjectFieldSelector {
                            field_path: "spec.nodeName".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
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
        let metadata = ObjectMeta {
            ..Default::default()
        };
        let result = validate_environment_variables(&podspec, &metadata, &settings);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);
        Ok(())
    }

    #[test]
    fn policy_should_validate_envvar_with_valuefrom_service_account_name_test() -> Result<(), ()> {
        let podspec = apicore::PodSpec {
            service_account_name: Some("value2".to_string()),
            containers: vec![apicore::Container {
                env: Some(vec![apicore::EnvVar {
                    name: "name2".to_string(),
                    value_from: Some(EnvVarSource {
                        field_ref: Some(ObjectFieldSelector {
                            field_path: "spec.serviceAccountName".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
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
        let metadata = ObjectMeta {
            ..Default::default()
        };
        let result = validate_environment_variables(&podspec, &metadata, &settings);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ANY_IN_ERROR_MSG);
        Ok(())
    }
}
