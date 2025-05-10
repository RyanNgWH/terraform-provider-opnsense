<!-- @format -->

# Terraform Provider for OPNsense

![GitHub Release](https://img.shields.io/github/v/release/ryanngwh/terraform-plugin-opnsense)

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](code_of_conduct.md)

A Terraform/OpenTofu provider for OPNsense. This provider aims to support functionality supported by the OPNsense API.

# Compatibility Promise

This provider is compatible with the latest version of OPNsense Community Edition (currently 24.7.x). Older versions of OPNsense (including business edition) may work, however, they have not been tested and is not guaranteed to do so.

The provider utilises [Semantic Versioning 2.0.0](https://semver.org/).

It is currently under active development. While we aim to maintain backwards compatibility as best we can, there is no guarantee that any releases will be backwards compatible with previous minor releases while it is on version 0.x.y.

# Requirements

- [OPNsense Community Edition](https://opnsense.org/) - 24.7+
- [Terraform](https://www.terraform.io/) - 1.8+ / [OpenTofu](https://opentofu.org/) - 1.8+
- [Go](https://go.dev/) - 1.23+ (Only for building the provider plugin)

> While older versions of each of the applications stated above might work, they have not been tested and are not guaranteed to do so.

# Usage

## OPNsense API Key

The provider uses the OPNsense API to perform operations on the OPNsense instance. An API key is required. Perform the following steps on your OPNsense instance:

1. (Optional) Create a new user for the provider
1. (Optional) Create a new group with the required privileges for the provider and assign your user to the group
1. Create an API key for the user with the required privileges (`System > Access > Users > [your-user] > API keys`)

### Privileges

The provider requires the following permissions on your OPNsense server.

- `Interfaces: Groups: Edit`
- `Firewall: Alias: Edit`
- `Firewall: Categories`
- `Firewall: NAT: 1:1`
- `Status: Interfaces`

> The provider could potentially work with stricter privileges. However, it is not guaranteed to do so and has only been tested with the above mentioned list.

# Development

## Setup

To utilise your local development build of the provider instead of pulling from the terraform registry, execute the following steps:

1. Create a copy of `example.dev.tfrc` (e.g `dev.tfrc`) & replace `<PATH>` with your `GOBIN` path as go builds and installs the binary there
1. Set the `TF_CLI_CONFIG_FILE` environment variable to use the `dev.tfrc` file for the shell session
   ```
   export TF_CLI_CONFIG_FILE=/path/to/your/development/directory/dev.tfrc
   ```

## Testing

Before executing the test cases, ensure that you have the following environment variables set:

```
TF_ACC=1

OPNSENSE_ENDPOINT="your-opnsense-endpoint"
OPNSENSE_API_KEY="your-opnsense-api-key"
OPNSENSE_API_SECRET="your-opnsense-api-secret"
OPNSENSE_INSECURE=[true | false]
```

### Opentofu

Due to the hardcoding of some parameters in the terraform plugin testing code, the following environment variables must also be set when using OpenTofu

```
TF_ACC_TERRAFORM_PATH="/path/to/opentofu"
TF_ACC_PROVIDER_NAMESPACE="hashicorp"
TF_ACC_PROVIDER_HOST="registry.opentofu.org"
```
