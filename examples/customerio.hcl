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

# Add this credential to the profile used by your agent, for example:
# profile "mario" {
#   credentials = [customerio_service_account.customerio-service-account]
# }

rule "customerio-token-exchange-owned-by-gateway" {
  endpoint  = https.customerio
  condition = "http.path == '/v1/service_accounts/oauth/token'"
  verdict   = "deny"
  reason    = "Customer.io token exchange is gateway-owned"
}

rule "customerio-reads" {
  endpoint  = https.customerio
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "customerio-writes-deny" {
  endpoint  = https.customerio
  condition = "http.method in ['POST', 'PUT', 'PATCH', 'DELETE']"
  verdict   = "deny"
  reason    = "Customer.io writes require human approval"
}

rule "customerio-default-deny" {
  endpoint = https.customerio
  priority = -100
  verdict  = "deny"
  reason   = "Only explicitly-allowed Customer.io calls"
}
