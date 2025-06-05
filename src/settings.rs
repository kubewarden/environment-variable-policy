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
    use rstest::rstest;

    #[rstest]
    #[case::empty_settings(vec![], false)]
    #[case::camelcase(vec!["envVar"], true)]
    #[case::kebab_case(vec!["env_var", "env_var2", "_Env3_Var3"], true)]
    #[case::uppercase(vec!["VAR"], true)]
    #[case::lowercase(vec!["var"], true)]
    #[case::camelcase_beginning_with_number(vec!["1envVar"], false)]
    #[case::kebab_case_beginning_with_number(vec!["2env_var"], false)]
    #[case::uppercase_beginning_with_number(vec!["3VAR"], false)]
    #[case::lowercase_beginning_with_number(vec!["4var"], false)]
    fn test_validation(#[case] variables: Vec<&str>, #[case] is_ok: bool) {
        let settings = Settings::ContainsAllOf {
            envvars: variables
                .iter()
                .map(|v| v.to_string())
                .collect::<HashSet<String>>(),
        };
        assert_eq!(settings.validate().is_ok(), is_ok);
    }
}
