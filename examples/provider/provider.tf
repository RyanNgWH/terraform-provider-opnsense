provider "opnsense" {
  # May also be provided via the OPNSENSE_ENDPOINT environment variable
  endpoint = "https://172.28.28.129"
  # May also be provided via the OPNSENSE_API_KEY environment variable
  api_key = "opnsense-api-key"
  # May also be provided via the OPNSENSE_API_SECRET environment variable
  api_secret = "opnsense-api-secret"

  # Set to true if self-signed certificate is in use
  insecure = true
}
