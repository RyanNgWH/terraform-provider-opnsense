# Example geoip configuration using MaxMind
resource "opnsense_firewall_alias_geoip" "resource_example" {
  url = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=<your-license-key>&suffix=zip"
}
