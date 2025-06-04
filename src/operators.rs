use std::collections::HashSet;

use anyhow::{anyhow, Result};

pub(crate) const CONTAINS_ANY_OF_ERROR_MSG: &str =
    "Resource must have at least one of the required environment variables specified by the validation rule. None of the expected environment variables were found:";
pub(crate) const DOES_NOT_CONTAIN_ANY_OF_ERROR_MSG: &str =
    "Resource must not have any of the environment variables specified in the validation rule. The following invalid environment variables were found:";
pub(crate) const CONTAINS_ALL_OF_ERROR_MSG: &str =
    "Resource is missing required environment variables as specified in the validation rules. The following environment variables are missing:";
pub(crate) const DOES_NOT_CONTAIN_ALL_OF_ERROR_MSG: &str =
    "Resource has conflicting environment variables set according to the validation rules. The following environment variables should not be set together:";

pub(crate) fn contains_any_of(
    contains_any_of: &HashSet<String>,
    resource_env_var_names: &HashSet<String>,
) -> Result<()> {
    if contains_any_of.is_disjoint(resource_env_var_names) {
        let missing_envvar = contains_any_of
            .clone()
            .into_iter()
            .collect::<Vec<String>>()
            .join(", ");
        return Err(anyhow!("{CONTAINS_ANY_OF_ERROR_MSG} {missing_envvar}"));
    }
    Ok(())
}

pub(crate) fn does_not_contain_any_of(
    does_not_contains_any_of: &HashSet<String>,
    resource_env_var_names: &HashSet<String>,
) -> Result<()> {
    let invalid_envvars = does_not_contains_any_of
        .clone()
        .intersection(resource_env_var_names)
        .cloned()
        .collect::<Vec<String>>();
    if invalid_envvars.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "{DOES_NOT_CONTAIN_ANY_OF_ERROR_MSG} {}",
        invalid_envvars.join(", ")
    ))
}

pub(crate) fn contains_all_of(
    contains_all_of: &HashSet<String>,
    resource_env_var_names: &HashSet<String>,
) -> Result<()> {
    let missing_envvar = contains_all_of
        .difference(resource_env_var_names)
        .cloned()
        .collect::<Vec<String>>();
    if missing_envvar.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "{CONTAINS_ALL_OF_ERROR_MSG} {}",
        missing_envvar.join(", ")
    ))
}

pub(crate) fn does_not_contain_all_of(
    does_not_contains_all_of: &HashSet<String>,
    resource_env_var_names: &HashSet<String>,
) -> Result<()> {
    if does_not_contains_all_of.is_subset(resource_env_var_names) {
        let invalid_envvars = does_not_contains_all_of
            .iter()
            .cloned()
            .collect::<Vec<String>>()
            .join(", ");
        return Err(anyhow!(
            "{DOES_NOT_CONTAIN_ALL_OF_ERROR_MSG} {invalid_envvars}"
        ));
    }
    Ok(())
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

        let result = contains_any_of(&default_envvar, &resource_env_var_names);
        if is_ok {
            result.expect("Expected validation to pass");
        } else {
            let error = result.expect_err("Expected validation to fail");
            assert!(
                error.to_string().contains(CONTAINS_ANY_OF_ERROR_MSG),
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

        let result = does_not_contain_any_of(&default_envvar, &resource_env_var_names);
        if is_ok {
            result.expect("Expected validation to pass");
        } else {
            let error = result.expect_err("Expected validation to fail");
            assert!(
                error
                    .to_string()
                    .contains(DOES_NOT_CONTAIN_ANY_OF_ERROR_MSG),
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

        let result = contains_all_of(&default_envvar, &resource_env_var_names);
        if is_ok {
            result.expect("Expected validation to pass");
        } else {
            let error = result.expect_err("Expected validation to fail");
            assert!(
                error.to_string().contains(CONTAINS_ALL_OF_ERROR_MSG),
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
    fn test_does_not_container_all_of(#[case] envvar: Vec<&str>, #[case] is_ok: bool) {
        let default_envvar = HashSet::from(["a".to_owned(), "b".to_owned()]);
        let resource_env_var_names: HashSet<String> =
            envvar.into_iter().map(|v| v.to_string()).collect();

        let result = does_not_contain_all_of(&default_envvar, &resource_env_var_names);
        if is_ok {
            result.expect("Expected validation to pass");
        } else {
            let error = result.expect_err("Expected validation to fail");
            assert!(
                error
                    .to_string()
                    .contains(DOES_NOT_CONTAIN_ALL_OF_ERROR_MSG),
                "Validation error message does not contain expected text"
            );
        }
    }
}
