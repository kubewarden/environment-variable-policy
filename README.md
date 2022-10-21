[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/environment-variable-policy)](https://artifacthub.io/packages/search?repo=environment-variable-policy)

# environment-variable-policy

The environment-variable-policy can be used to inspect environment variables
defined in the resources deployed in the cluster. It's able to validate both
variables names and values. The policy allows the users define multiple validation rules.
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
    - reject: anyIn
      environmentVariables:
        - name: "envvar1"
          value: "envvar1_value"
        - name: "envvar2"
          value: "envvar2_value"

```

The supported `reject` operator are:


- `anyIn` (default): checks if any of the `environmentVariables` are in the Pod/Workload resource
- `anyNotIn`: checks if any of the `environmentVariables` are not in the Pod/Workload resource
- `allAreUsed`: checks if all of the `environmentVariables` are in the Pod/Workload resource
- `notAllAreUsed`: checks if all of the `environmentVariables` are not in the Pod/Workload resource

The environment variables are defined as objects:
```yaml
- name: "variable name"
  value: "variable value"
```

The name should follow the  [C_IDENTIFIER](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/#envvar-v1-core)
standard and the `value` field is optional. When it is not define the `""` value is used by default.

It is not allowed define a rule with an empty `environmentVariables` list.

## Examples

In the following example, the resources that have least one of the variables will be denied:

```yaml
settings:
  rules:
    - reject: anyIn
      environmentVariables:
        - name: "envvar1"
        - name: "envvar2"

```

In the following example, the resources cannot use both environment variables at once, only one or the other

```yaml
settings:
  rules:
    - reject: allAreUsed
      environmentVariables:
        - name: "envvar2"
          value: ""
```

In the following example, only resources that have the `envvar3` or `envvar2` defined will be allowed:

```yaml
settings:
  rules:
    - reject: anyNotIn
      environmentVariables:
        - name: "envvar2"
          value: "envvar2_value"
        - name: "envvar3"
```

In the following example, the resources can use both variables at once, but not only one of them

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

## License

```
Copyright (C) 2021 José Guilherme Vanz <jvanz@jvanz.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
