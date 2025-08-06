use std::collections::HashSet;

use anyhow::{Result, anyhow};

pub fn contains_any_of_error_msg(resource_type: &str) -> String {
    format!(
        "Resource must have at least one of the required {resource_type}s specified by the validation rule. None of the expected {resource_type}s were found:"
    )
}
pub fn does_not_contain_any_of_error_msg(resource_type: &str) -> String {
    format!(
        "Resource must not have any of the {resource_type}s specified in the validation rule. The following invalid {resource_type}s were found:",
    )
}
pub fn contains_all_of_error_msg(resource_type: &str) -> String {
    format!(
        "Resource is missing required {resource_type}s as specified in the validation rules. The following {resource_type}s are missing:",
    )
}
pub fn does_not_contain_all_of_error_msg(resource_type: &str) -> String {
    format!(
        "Resource has conflicting {resource_type}s set according to the validation rules. The following {resource_type}s should not be set together:",
    )
}
pub fn contains_other_than_error_msg(resource_type: &str) -> String {
    format!(
        "Resource must not have any {resource_type}s other than those specified in the validation rule. The following {resource_type}s were found that should not be present:",
    )
}
pub fn does_not_contain_other_than_error_msg(resource_type: &str) -> String {
    format!(
        "Resource must have only {resource_type}s from the validation rule. The following {resource_type}s were found that should not be present:",
    )
}

pub fn contains_any_of(
    contains_any_of: &HashSet<String>,
    resource_names: &HashSet<String>,
    resource_type: &str,
) -> Result<()> {
    if contains_any_of.is_disjoint(resource_names) {
        let missing = contains_any_of.clone().into_iter().collect::<Vec<String>>();
        return Err(anyhow!(
            "{} {}",
            contains_any_of_error_msg(resource_type),
            missing.join(", ")
        ));
    }
    Ok(())
}

// implements a denylist
pub fn does_not_contain_any_of(
    does_not_contains_any_of: &HashSet<String>,
    resource_names: &HashSet<String>,
    resource_type: &str,
) -> Result<()> {
    let invalid = does_not_contains_any_of
        .clone()
        .intersection(resource_names)
        .cloned()
        .collect::<Vec<String>>();
    if invalid.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "{} {}",
        does_not_contain_any_of_error_msg(resource_type),
        invalid.join(", ")
    ))
}

pub fn contains_all_of(
    contains_all_of: &HashSet<String>,
    resource_names: &HashSet<String>,
    resource_type: &str,
) -> Result<()> {
    let missing = contains_all_of
        .difference(resource_names)
        .cloned()
        .collect::<Vec<String>>();
    if missing.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "{} {}",
        contains_all_of_error_msg(resource_type),
        missing.join(", ")
    ))
}

pub fn does_not_contain_all_of(
    does_not_contain_all_of: &HashSet<String>,
    resource_names: &HashSet<String>,
    resource_type: &str,
) -> Result<()> {
    if does_not_contain_all_of.is_subset(resource_names) {
        let invalid = does_not_contain_all_of
            .iter()
            .cloned()
            .collect::<Vec<String>>();
        return Err(anyhow!(
            "{} {}",
            does_not_contain_all_of_error_msg(resource_type),
            invalid.join(", ")
        ));
    }
    Ok(())
}

pub fn contains_other_than(
    contains_other_than: &HashSet<String>,
    resource_names: &HashSet<String>,
    resource_type: &str,
) -> Result<()> {
    if resource_names.is_subset(contains_other_than) {
        let invalid = resource_names
            .difference(contains_other_than)
            .cloned()
            .collect::<Vec<String>>();
        Err(anyhow!(
            "{} {}",
            contains_other_than_error_msg(resource_type),
            invalid.join(", ")
        ))
    } else {
        Ok(())
    }
}

// implements an allowlist
pub fn does_not_contain_other_than(
    does_not_contain_other_than: &HashSet<String>,
    resource_names: &HashSet<String>,
    resource_type: &str,
) -> Result<()> {
    if resource_names.is_subset(does_not_contain_other_than) {
        Ok(())
    } else {
        let invalid = resource_names
            .difference(does_not_contain_other_than)
            .cloned()
            .collect::<Vec<String>>();
        Err(anyhow!(
            "{} {}",
            does_not_contain_other_than_error_msg(resource_type),
            invalid.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::collections::HashSet;

    #[rstest]
    #[case(vec!["a"], true)]
    #[case(vec!["a","b"], true)]
    #[case(vec!["a","b", "c"], true)]
    #[case(vec!["c"], false)]
    #[case(vec!["b", "c"], true)]
    #[case(vec![ ], false)]
    fn test_contains_any_of(#[case] envvar: Vec<&str>, #[case] is_ok: bool) {
        let default_envvar = HashSet::from(["a".to_owned(), "b".to_owned()]);
        let resource_env_var_names: HashSet<String> =
            envvar.into_iter().map(|v| v.to_string()).collect();

        let result = contains_any_of(&default_envvar, &resource_env_var_names, "envvar");
        if is_ok {
            result.expect("Expected validation to pass");
        } else {
            let error = result.expect_err("Expected validation to fail");
            assert!(
                error
                    .to_string()
                    .contains(&contains_any_of_error_msg("envvar")),
                "Validation error message does not contain expected text"
            );
        }
    }

    #[rstest]
    #[case(vec!["a"], false)]
    #[case(vec!["a","b"], false)]
    #[case(vec!["a","b","c"], false)]
    #[case(vec!["c"], true)]
    #[case(vec!["b", "c"], false)]
    #[case(vec![ ], true)]
    fn test_does_not_contain_any_of(#[case] envvar: Vec<&str>, #[case] is_ok: bool) {
        let default_envvar = HashSet::from(["a".to_owned(), "b".to_owned()]);
        let resource_env_var_names: HashSet<String> =
            envvar.into_iter().map(|v| v.to_string()).collect();

        let result = does_not_contain_any_of(&default_envvar, &resource_env_var_names, "envvar");
        if is_ok {
            result.expect("Expected validation to pass");
        } else {
            let error = result.expect_err("Expected validation to fail");
            assert!(
                error
                    .to_string()
                    .contains(&does_not_contain_any_of_error_msg("envvar")),
                "Validation error message does not contain expected text"
            );
        }
    }

    #[rstest]
    #[case(vec![ "a"], false)]
    #[case(vec![ "a", "b"], true)]
    #[case(vec![ "a", "b","c"], true)]
    #[case(vec![ "c"], false)]
    #[case(vec![ "b", "c"], false)]
    #[case(vec![ ], false)]
    fn test_contains_all_of(#[case] envvar: Vec<&str>, #[case] is_ok: bool) {
        let default_envvar = HashSet::from(["a".to_owned(), "b".to_owned()]);
        let resource_env_var_names: HashSet<String> =
            envvar.into_iter().map(|v| v.to_string()).collect();

        let result = contains_all_of(&default_envvar, &resource_env_var_names, "envvar");
        if is_ok {
            result.expect("Expected validation to pass");
        } else {
            let error = result.expect_err("Expected validation to fail");
            assert!(
                error
                    .to_string()
                    .contains(&contains_all_of_error_msg("envvar")),
                "Validation error message does not contain expected text"
            );
        }
    }

    #[rstest]
    #[case(vec!["a"], true)]
    #[case(vec!["b"], true)]
    #[case(vec!["a","b"], false)]
    #[case(vec!["a","b","c"], false)]
    #[case(vec!["c"], true)]
    #[case(vec!["b","c"], true)]
    #[case(vec![ ], true)]
    fn test_does_not_contain_all_of(#[case] envvar: Vec<&str>, #[case] is_ok: bool) {
        let default_envvar = HashSet::from(["a".to_owned(), "b".to_owned()]);
        let resource_env_var_names: HashSet<String> =
            envvar.into_iter().map(|v| v.to_string()).collect();

        let result = does_not_contain_all_of(&default_envvar, &resource_env_var_names, "envvar");
        if is_ok {
            result.expect("Expected validation to pass");
        } else {
            let error = result.expect_err("Expected validation to fail");
            assert!(
                error
                    .to_string()
                    .contains(&does_not_contain_all_of_error_msg("envvar")),
                "Validation error message does not contain expected text"
            );
        }
    }

    #[rstest]
    #[case(vec![ "a"], false)]
    #[case(vec![ "a", "b"], false)]
    #[case(vec![ "a", "b","c"], true)]
    #[case(vec![ "c"], true)]
    #[case(vec![ "b", "c"], true)]
    #[case(vec![ ], false)]
    fn test_contains_other_than(#[case] envvar: Vec<&str>, #[case] is_ok: bool) {
        let default_envvar = HashSet::from(["a".to_owned(), "b".to_owned()]);
        let resource_env_var_names: HashSet<String> =
            envvar.into_iter().map(|v| v.to_string()).collect();

        let result = contains_other_than(&default_envvar, &resource_env_var_names, "envvar");
        if is_ok {
            result.expect("Expected validation to pass");
        } else {
            let error = result.expect_err("Expected validation to fail");
            assert!(
                error
                    .to_string()
                    .contains(&contains_other_than_error_msg("envvar")),
                "Validation error message does not contain expected text"
            );
        }
    }

    #[rstest]
    #[case(vec![ "a"], true)]
    #[case(vec![ "a", "b"], true)]
    #[case(vec![ "a", "b","c"], false)]
    #[case(vec![ "c"], false)]
    #[case(vec![ "b", "c"], false)]
    #[case(vec![ ], true)]
    fn test_does_not_contain_other_than(#[case] envvar: Vec<&str>, #[case] is_ok: bool) {
        let default_envvar = HashSet::from(["a".to_owned(), "b".to_owned()]);
        let resource_env_var_names: HashSet<String> =
            envvar.into_iter().map(|v| v.to_string()).collect();

        let result =
            does_not_contain_other_than(&default_envvar, &resource_env_var_names, "envvar");
        if is_ok {
            result.expect("Expected validation to pass");
        } else {
            let error = result.expect_err("Expected validation to fail");
            assert!(
                error
                    .to_string()
                    .contains(&does_not_contain_other_than_error_msg("envvar")),
                "Validation error message does not contain expected text"
            );
        }
    }
}
