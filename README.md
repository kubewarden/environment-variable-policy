[![Kubewarden Policy Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-policies.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#policy-scope)
[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

# environment-variable-policy

The environment-variable-policy can be used to inspect environment variables
defined in the resources deployed in the cluster. It's able to validate both
variables names and values. The policy allows the users to define multiple
validation rules. And the resource must pass **all** the rules to be allowed in
the cluster.

The policy can either target Pods, or workload resources (Deployments,
ReplicaSets, DaemonSets, ReplicationControllers, Jobs, CronJobs). Both have
trade-offs:

- Policy targets Pods: Different kind of resources (be them native or CRDs) can
  create Pods. By having the policy target Pods, we guarantee that all the Pods
  are going to be compliant, even those created from CRDs. However, this could
  lead to confusion among users, as high level Kubernetes resources would be
  successfully created, but they would stay in a non reconciled state. Example:
  a Deployment creating a non-compliant Pod would be created, but it would
  never have all its replicas running.

- Policy targets workload resources (e.g: Deployment): the policy inspect
  higher order resource (e.g. Deployment): users will get immediate feedback
  about rejections. However, non compliant pods created by another high level
  resource (be it native to Kubernetes, or a CRD), may not get rejected.

## Settings

Each rule defined in the policy settings is composed by a `reject` operator and
a set of the environment variable used with the operator against the
environment variables from the resources. The rules are evaluated in the order
that they are defined. The resource is denied in the first failed evaluated
rule. The following yaml is a settings example:

```yaml
settings:
  rules:
    - reject: anyIn
      environmentVariables:
        - name: "envvar1"
          value: "envvar1_value"
        - name: "envvar2"
          value: "envvar2_value"

```

The supported `reject` operator are:


- `anyIn` (default): rejects if **any** (at least one) of the
  `environmentVariables` are defined in the  resource
- `anyNotIn:` rejects if **any**  (at least one) of the `environmentVariables`
  are **missing** in the  resource
- `allAreUsed`: rejects if **all** of the `environmentVariables` are defined in
  the resource. 
- `notAllAreUsed` : rejects if **all** of the `environmentVariables` are
  **missing** in the  resource

The environment variables are defined as objects:
```yaml
- name: "variable name"
  value: "variable value"
```

The name should follow the
[C_IDENTIFIER](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/#envvar-v1-core)
standard and the `value` field is optional. When it is not define the `""`
value is used by default.

It is not allowed define a rule with an empty `environmentVariables` list.

## Examples

In the following example, the resources that have least one of the variables
will be denied:

```yaml
settings:
  rules:
    - reject: anyIn
      environmentVariables:
        - name: "envvar1"
        - name: "envvar2"

```

In the following example, only resources that does have `envvar3` and `envvar2`
defined will be allowed. If any of the variable are missing, the resource will
be denied:

```yaml
settings:
  rules:
    - reject: anyNotIn
      environmentVariables:
        - name: "envvar2"
          value: "envvar2_value"
        - name: "envvar3"
```

In the following example, the resources cannot use both environment variables
at once, only one or the other

```yaml
settings:
  rules:
    - reject: allAreUsed
      environmentVariables:
        - name: "envvar2"
          value: "value2"
        - name: "envvar3"
          value: "value3"
```


In the following example, the resources missing  both variables  will be
rejected. If any of the variable are defined, the resource will be allowed:

```yaml
settings:
  rules:
    - reject: notAllAreUsed
      environmentVariables:
        - name: "envvar3"
          value: "envvar3_value"
        - name: "envvar4"
          value: "envvar4_value"
```
