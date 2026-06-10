# Claw Patrol Customer.io credential plugin

External Claw Patrol credential plugin for Customer.io service-account tokens.

This is a proof of concept for Claw Patrol's external HTTP credential runtime. The gateway stores the raw Customer.io service-account token (`sa_live_...`, `sa_sandbox_...`, or `sa_test_...`), exchanges it for a short-lived Customer.io JWT, and injects that JWT into intercepted Customer.io HTTPS requests.

## Credential type

```hcl
plugin "customerio" {
  source = "/opt/clawpatrol/plugins/clawpatrol-customerio-plugin"
}

endpoint "https" "customerio" {
  hosts = ["eu.fly.customer.io"]
}

credential "customerio_service_account" "customerio-service-account" {
  endpoint    = https.customerio
  region      = "eu"
  read_only   = true
  placeholder = "PH_customerio_access"
}
```

See `examples/customerio.hcl` for deny-by-default read-only rules.

## Pushed environment variables

The credential publishes placeholders for the common Customer.io CLIs:

- `CUSTOMERIO_TOKEN=PH_customerio_access`
- `CUSTOMER_IO_BASE_URL=https://<region>.fly.customer.io`
- `CUSTOMERIO_REGION=<region>`
- `CIO_ACCESS_TOKEN=PH_customerio_access`
- `CIO_TOKEN=PH_customerio_access`
- `CIO_API_URL=https://<region>.fly.customer.io`
- `CIO_REGION=<region>`
- `CIO_AGENT=1`

## Build

Until the external credential runtime lands upstream, build this next to a Claw Patrol checkout that contains the `pluginsdk` changes:

```bash
git clone https://github.com/dhruvkelawala/clawpatrol.git
cd clawpatrol
git checkout external-http-credential-runtime
cd ..

git clone https://github.com/dhruvkelawala/clawpatrol-customerio-plugin.git
cd clawpatrol-customerio-plugin
go test ./...
go build -o clawpatrol-customerio-plugin .
```

The temporary `replace github.com/denoland/clawpatrol => ../clawpatrol` in `go.mod` is intentional for this POC.

## Gateway install sketch

```bash
sudo install -m 0755 clawpatrol-customerio-plugin /opt/clawpatrol/plugins/clawpatrol-customerio-plugin
sudo systemctl restart clawpatrol-gateway.service
```

Then connect the dashboard credential using the raw Customer.io service-account token. Do not put the real token in HCL or environment files.

## Test ideas

Direct placeholder should fail:

```bash
CIO_ACCESS_TOKEN=PH_customerio_access CIO_API_URL=https://eu.fly.customer.io cio api /v1/accounts/current
```

Through Claw Patrol, the same placeholder should be replaced by a short-lived JWT:

```bash
clawpatrol run -- cio api /v1/accounts/current
clawpatrol run -- customer-io --agent workspaces list
```

With the read-only example rules, writes should be denied by Claw Patrol unless you explicitly add an approval/allow path.
