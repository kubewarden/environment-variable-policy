use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::enum_variant_names)] // allow for all to end in `In`
pub(crate) struct EnvVar {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::enum_variant_names)] // allow for all to end in `In`
pub enum Operator {
    AllAreUsed,
    NotAllAreUsed,
    #[default]
    AnyIn,
    AnyNotIn,
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Rule {
    pub reject: Operator,
    pub environment_variables: HashSet<EnvVar>,
}

// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Settings {
    pub rules: Vec<Rule>,
}

// Regex used to validate the environment variable name. It should allow
// only C_IDENTIFIERS names.
const ENVIRONMENT_VARIABLE_NAME_REGEX: &str = r"^[a-zA-Z_][a-zA-Z_\d]*$";

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        if self.rules.is_empty() {
            return Err("Define at least one rule".to_string());
        }
        let has_empty_rule = self
            .rules
            .iter()
            .map(|rule| rule.environment_variables.len())
            .any(|len| len == 0);
        if has_empty_rule {
            return Err("Rule with no environment variables defined is not allowed.".to_string());
        }
        let environment_variable_name_regex = Regex::new(ENVIRONMENT_VARIABLE_NAME_REGEX).unwrap();
        let all_envvar_valid = self
            .rules
            .iter()
            .flat_map(|rule| rule.environment_variables.clone())
            .map(|envvar| envvar.name)
            .all(|envvar| environment_variable_name_regex.is_match(&envvar));
        if !all_envvar_valid {
            return Err("Invalid environment variable name.".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_empty_rules_settings() -> Result<(), ()> {
        let settings = Settings { rules: vec![] };
        assert!(
            settings.validate().is_err(),
            "Settings should contains at least one rule"
        );
        Ok(())
    }
    #[test]
    fn validate_rule_with_no_envvar_settings() -> Result<(), ()> {
        let settings = Settings {
            rules: vec![Rule {
                environment_variables: HashSet::from([]),
                ..Default::default()
            }],
        };
        assert!(
            settings.validate().is_err(),
            "Settings should not accept rule with no environment variables"
        );
        Ok(())
    }

    #[test]
    fn settings_should_allow_envvar_name() -> Result<(), ()> {
        let settings = Settings {
            rules: vec![Rule {
                environment_variables: HashSet::from([
                    EnvVar {
                        name: "envvar".to_string(),
                        value: None,
                    },
                    EnvVar {
                        name: "env_var2".to_string(),
                        value: None,
                    },
                    EnvVar {
                        name: "_env_var3".to_string(),
                        value: None,
                    },
                ]),
                ..Default::default()
            }],
        };
        assert!(
            settings.validate().is_ok(),
            "Environment variables should allow only names."
        );
        Ok(())
    }

    #[test]
    fn settings_should_allow_envvar_name_and_value() -> Result<(), ()> {
        let settings = Settings {
            rules: vec![Rule {
                environment_variables: HashSet::from([
                    EnvVar {
                        name: "envvar".to_string(),
                        value: Some("value1".to_string()),
                    },
                    EnvVar {
                        name: "env_var2".to_string(),
                        value: Some("value_2".to_string()),
                    },
                    EnvVar {
                        name: "_env_var3".to_string(),
                        value: Some("value3!".to_string()),
                    },
                ]),
                ..Default::default()
            }],
        };
        assert!(
            settings.validate().is_ok(),
            "Environment variables should allow name and value"
        );
        Ok(())
    }

    #[test]
    fn settings_should_allow_envvar_name_and_value_mixed() -> Result<(), ()> {
        let settings = Settings {
            rules: vec![Rule {
                environment_variables: HashSet::from([
                    EnvVar {
                        name: "envvar".to_string(),
                        value: None,
                    },
                    EnvVar {
                        name: "env_var2".to_string(),
                        value: Some("value2".to_string()),
                    },
                    EnvVar {
                        name: "_env_var3".to_string(),
                        value: Some("value3".to_string()),
                    },
                ]),
                ..Default::default()
            }],
        };
        assert!(
            settings.validate().is_ok(),
            "Environment variables should allow mix only names and name with values"
        );
        Ok(())
    }

    #[test]
    fn settings_should_allow_envvar_with_empty_value() -> Result<(), ()> {
        let settings = Settings {
            rules: vec![Rule {
                environment_variables: HashSet::from([
                    EnvVar {
                        name: "envvar".to_string(),
                        value: None,
                    },
                    EnvVar {
                        name: "env_var2".to_string(),
                        value: Some("".to_string()),
                    },
                    EnvVar {
                        name: "_env_var3".to_string(),
                        value: Some("".to_string()),
                    },
                ]),
                ..Default::default()
            }],
        };
        assert!(
            settings.validate().is_ok(),
            "Environment variables should allow empty values"
        );
        Ok(())
    }

    #[test]
    fn settings_should_not_allow_envvar_beginning_with_numbers() -> Result<(), ()> {
        let settings = Settings {
            rules: vec![Rule {
                environment_variables: HashSet::from([
                    EnvVar {
                        name: "1envvar".to_string(),
                        value: None,
                    },
                    EnvVar {
                        name: "2envvar2".to_string(),
                        value: Some("".to_string()),
                    },
                    EnvVar {
                        name: "3env_var3".to_string(),
                        value: Some("value".to_string()),
                    },
                    EnvVar {
                        name: "4_env_var4".to_string(),
                        value: Some("value".to_string()),
                    },
                ]),
                ..Default::default()
            }],
        };
        assert!(
            settings.validate().is_err(),
            "Environment variables should not beginning with digits"
        );
        Ok(())
    }

    #[test]
    fn name_regex_validation_should_not_allow_name_starting_with_numbers_test() -> Result<(), ()> {
        let environment_variable_name_regex = Regex::new(ENVIRONMENT_VARIABLE_NAME_REGEX).unwrap();
        assert_eq!(environment_variable_name_regex.is_match("1envvar"), false);
        assert_eq!(environment_variable_name_regex.is_match("2envvar2"), false);
        assert_eq!(environment_variable_name_regex.is_match("3env_var3"), false);
        assert_eq!(
            environment_variable_name_regex.is_match("4_env_var4"),
            false
        );
        Ok(())
    }

    #[test]
    fn name_regex_validation_should_allow_c_identifier_names_test() -> Result<(), ()> {
        let environment_variable_name_regex = Regex::new(ENVIRONMENT_VARIABLE_NAME_REGEX).unwrap();
        println!("{}", environment_variable_name_regex.is_match("envvar"));
        assert!(environment_variable_name_regex.is_match("envvar"));
        assert!(environment_variable_name_regex.is_match("EnvVar"));
        assert!(environment_variable_name_regex.is_match("env_var2"));
        assert!(environment_variable_name_regex.is_match("Env_var2"));
        assert!(environment_variable_name_regex.is_match("_env_var3"));
        assert!(environment_variable_name_regex.is_match("_env3_var3"));
        assert!(environment_variable_name_regex.is_match("_Env3_Var3"));
        Ok(())
    }

    #[test]
    fn settings_serialization_test() -> Result<(), ()> {
        let yaml = r#"
          rules:
            - reject: "allAreUsed"
              environmentVariables:
                - name: "envar"
                  value: "envvar value"
        "#;
        let settings: Settings = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(settings.rules.len(), 1);
        assert_eq!(settings.rules[0].reject, Operator::AllAreUsed);
        assert_eq!(settings.rules[0].environment_variables.len(), 1);
        for envvar in settings.rules[0].environment_variables.iter() {
            assert_eq!(envvar.name.as_ref(), "envar".to_string());
            assert_eq!(envvar.value.as_ref().unwrap(), "envvar value");
        }
        Ok(())
    }

    #[test]
    fn validate_rule_hash_test() -> Result<(), ()> {
        let mut set = HashSet::new();
        set.insert(EnvVar {
            name: "envvar".to_string(),
            value: Some("value".to_string()),
        });
        set.insert(EnvVar {
            name: "envvar".to_string(),
            value: Some("value".to_string()),
        });
        assert_eq!(set.len(), 1);
        set.insert(EnvVar {
            name: "envvar2".to_string(),
            value: Some("value".to_string()),
        });
        assert_eq!(set.len(), 2);
        set.insert(EnvVar {
            name: "envvar2".to_string(),
            value: Some("value2".to_string()),
        });
        assert_eq!(set.len(), 3);
        Ok(())
    }
}
