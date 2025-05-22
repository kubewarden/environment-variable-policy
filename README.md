[![Kubewarden Policy Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-policies.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#policy-scope)
[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

# environment-variable-policy

The environment-variable-policy can be used to inspect environment variables
defined in the resources deployed in the cluster. The policy allows the users define multiple validation rules.
And the resource must pass **all** the rules to be allowed in the cluster.

The policy can either target Pods, or workload resources (Deployments, ReplicaSets,
DaemonSets, ReplicationControllers, Jobs, CronJobs). Both have trade-offs:

- Policy targets Pods: Different kind of resources (be them native or CRDs) can
  create Pods. By having the policy target Pods, we guarantee that all the Pods
  are going to be compliant, even those created from CRDs. However, this could
  lead to confusion among users, as high level Kubernetes resources would be
  successfully created, but they would stay in a non reconciled state.
  Example: a Deployment creating a non-compliant Pod would be created, but it
  would never have all its replicas running.

- Policy targets workload resources (e.g: Deployment): the policy inspect higher
  order resource (e.g. Deployment): users will get immediate feedback about rejections.
  However, non compliant pods created by another high level resource (be it native
  to Kubernetes, or a CRD), may not get rejected.

## Settings

Each rule defined in the policy settings is composed by a `reject` operator and a set
of the environment variable used with the operator against the environment variables
from the resources. The rules are evaluated in the order that they are defined.
The resource is denied in the first failed evaluated rule. The following yaml is a settings example:

```yaml
settings:
  rules:
    - reject: containsAnyOf
      environmentVariables:
        - "envvar1"
        - "envvar2"
```

The supported `reject` operator are:

- `containsAnyOf` (default): enforces that the resource has at least one of the
  `environmentVariables`.
- `doesNotContainAnyOf`: enforces that the resource does not have any environment
  variable defined in `environmentVariables`. It's the opposite of `anyIn`.
- `containsAllOf`: enforces that all of the `environmentVariables` are defined in
  the resource.
- `doesNotContainAllOf`: enforces that the `environmentVariables` are not all set
  together in the resource. It's the opposite of `allAreUsed`.

The environment variables names should follow the [C_IDENTIFIER](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/#envvar-v1-core)
standard. And it is not allowed define a rule with an empty `environmentVariables` list.

## Examples

Some tables to help you understand the logic of the operators:

### `containsAnyOf`

Given these `environmentVariables` settings: `[a, b]`

| Resource environment variables | Evaluation result |
| ------------------------------ | ----------------- |
| a                              | Accepted          |
| b                              | Accepted          |
| a,b                            | Accepted          |
| a,b,c                          | Accepted          |
| c                              | Rejected          |
| a, c                           | Accepted          |
| b, c                           | Accepted          |
| empty                          | Rejected          |

### `doesNotContainAnyOf`

Given these `environmentVariables` settings: `[a, b]`

| Resource environment variables | Evaluation result |
| ------------------------------ | ----------------- |
| a                              | Rejected          |
| b                              | Rejected          |
| a,b                            | Rejected          |
| a,b,c                          | Rejected          |
| c                              | Accepted          |
| a, c                           | Rejected          |
| b, c                           | Rejected          |
| empty                          | Accepted          |

### `containsAllOf`

Given these `environmentVariables` settings: `[a, b]`

| Resource environment variables | Evaluation result |
| ------------------------------ | ----------------- |
| a                              | Rejected          |
| b                              | Rejected          |
| a,b                            | Accepted          |
| a,b,c                          | Accepted          |
| c                              | Rejected          |
| a, c                           | Rejected          |
| b, c                           | Rejected          |
| empty                          | Rejected          |

### `doesNotContainAllOf`

Given these `environmentVariables` settings: `[a, b]`

| Resource environment variables | Evaluation result |
| ------------------------------ | ----------------- |
| a                              | Accepted          |
| b                              | Accepted          |
| a,b                            | Rejected          |
| a,b,c                          | Rejected          |
| c                              | Accepted          |
| a, c                           | Accepted          |
| b, c                           | Accepted          |
| empty                          | Accepted          |
