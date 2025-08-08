use std::collections::HashSet;

use operators::kubewarden_policy_sdk as kubewarden;
use operators::settings::BaseSettings;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Settings(pub(crate) BaseSettings);

// It's not possible to use the Default in the derive macro because we cannot
// set a #[default] attribute to enum item that is no unit enums.
impl Default for Settings {
    fn default() -> Self {
        Settings(BaseSettings::ContainsAnyOf {
            values: HashSet::new(),
        })
    }
}

// Regex used to validate the environment variable name. It should allow
// only C_IDENTIFIERS names.
const ENVIRONMENT_VARIABLE_NAME_REGEX: &str = r"^[a-zA-Z_][a-zA-Z_\d]*$";

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        self.0.validate()?;

        let envvars = self.0.values();

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

    use operators::kubewarden_policy_sdk::settings::Validatable;
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
        let settings = Settings(BaseSettings::ContainsAllOf {
            values: variables
                .iter()
                .map(|v| v.to_string())
                .collect::<HashSet<String>>(),
        });
        assert_eq!(settings.validate().is_ok(), is_ok);
    }
}
