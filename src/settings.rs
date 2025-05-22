use std::collections::HashSet;

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "criteria")]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Settings {
    ContainsAllOf { envvars: HashSet<String> },
    DoesNotContainAllOf { envvars: HashSet<String> },
    ContainsAnyOf { envvars: HashSet<String> },
    DoesNotContainAnyOf { envvars: HashSet<String> },
}

// It's not possible to use the Default in the derive macro because we cannot
// set a #[default] attribute to enum item that is no unit enums.
impl Default for Settings {
    fn default() -> Self {
        Settings::ContainsAnyOf {
            envvars: HashSet::new(),
        }
    }
}

// Regex used to validate the environment variable name. It should allow
// only C_IDENTIFIERS names.
const ENVIRONMENT_VARIABLE_NAME_REGEX: &str = r"^[a-zA-Z_][a-zA-Z_\d]*$";

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        let envvars = match self {
            Settings::ContainsAllOf { envvars } => envvars,
            Settings::DoesNotContainAllOf { envvars } => envvars,
            Settings::ContainsAnyOf { envvars } => envvars,
            Settings::DoesNotContainAnyOf { envvars } => envvars,
        };
        if envvars.is_empty() {
            return Err("Empty environment variable list is not allowed".to_string());
        }

        // Validate that the environment variable names are valid.
        let environment_variable_name_regex = Regex::new(ENVIRONMENT_VARIABLE_NAME_REGEX).unwrap();
        let invalid_envvar: Vec<String> = envvars
            .iter()
            .filter_map(|envvar| {
                if environment_variable_name_regex.is_match(envvar) {
                    return None;
                }
                Some(envvar.to_string())
            })
            .collect();
        if !invalid_envvar.is_empty() {
            return Err(format!(
                "Invalid environment variable names: {}",
                invalid_envvar.join(", "),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_empty_rules_settings() {
        let settings = Settings::ContainsAllOf {
            envvars: HashSet::new(),
        };
        assert!(
            settings.validate().is_err(),
            "Empty environment variable list is not allowed"
        );
    }

    #[test]
    fn settings_should_allow_envvar_name() {
        let settings = Settings::ContainsAnyOf {
            envvars: HashSet::from([
                "EnvVar".to_owned(),
                "Env_var2".to_owned(),
                "_Env3_Var3".to_owned(),
                "_env3_var3".to_owned(),
                "_env_var3".to_owned(),
                "env_var2".to_owned(),
                "envvar".to_owned(),
            ]),
        };
        assert!(
            settings.validate().is_ok(),
            "Environment variables should allow only names."
        );
    }

    #[test]
    fn settings_should_not_allow_envvar_beginning_with_numbers() {
        let settings = Settings::ContainsAnyOf {
            envvars: HashSet::from([
                "1envvar".to_owned(),
                "2envvar2".to_owned(),
                "3env_var3".to_owned(),
                "4_env_var4".to_owned(),
            ]),
        };
        assert!(
            settings.validate().is_err(),
            "Environment variables should not beginning with digits"
        );
    }
}
