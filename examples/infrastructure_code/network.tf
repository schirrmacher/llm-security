data "terraform_remote_state" "project" {
  backend   = "gcs"
  workspace = var.workspace_states["project"]
  config = {
    bucket = "pt-tfstate"
    prefix = "layer-project"
  }
}

locals {
  main_ip_range_split = split(".", google_compute_subnetwork.this.ip_cidr_range)
  main_ip_range       = join(".", [local.main_ip_range_split[0], local.main_ip_range_split[1]])
  project_id          = try(data.terraform_remote_state.project.outputs.project_id, "unknown-until-apply")
}

resource "google_compute_network" "this" {
  name                            = "vpc-pt-${terraform.workspace}"
  description                     = "Default VPC ${terraform.workspace}"
  routing_mode                    = "REGIONAL"
  project                         = local.project_id
  auto_create_subnetworks         = false
  delete_default_routes_on_create = false

  lifecycle { // This is needed because description changes recreate whole networks
    ignore_changes = [
      description
    ]
  }
}

resource "google_compute_subnetwork" "this" {
  name                     = "primary-network"
  project                  = local.project_id
  ip_cidr_range            = var.ip_addresses.primary.ip_cidr_range
  region                   = var.gcp_default_region
  network                  = google_compute_network.this.id
  private_ip_google_access = true

  dynamic "secondary_ip_range" {
    for_each = var.ip_addresses.primary.secondary_ip_range
    content {
      range_name    = secondary_ip_range.value.name
      ip_cidr_range = secondary_ip_range.value.cidr
    }
  }
}

resource "google_vpc_access_connector" "connector" {
  name = "gke-access"

  project       = local.project_id
  ip_cidr_range = "${local.main_ip_range}.254.0/28"
  network       = "vpc-pt-${terraform.workspace}"
}


resource "google_compute_subnetwork" "sub" {
  for_each                 = var.ip_addresses.subnetworks
  name                     = each.key
  project                  = local.project_id
  ip_cidr_range            = each.value.ip_cidr_range
  region                   = try(each.value.network_region, var.gcp_default_region)
  network                  = google_compute_network.this.id
  private_ip_google_access = each.value.private_ip_google_access
  purpose                  = try(each.value.purpose, "PRIVATE")
  role                     = each.value.purpose == "INTERNAL_HTTPS_LOAD_BALANCER" || each.value.purpose == "REGIONAL_MANAGED_PROXY" ? "ACTIVE" : null
}

####################################################################################################################
# NAT gateway configuration for outbound traffic.
####################################################################################################################

resource "google_compute_router" "this" {
  project     = local.project_id
  name        = "default"
  description = "Default router for outbound traffic"
  network     = google_compute_network.this.id
  region      = var.gcp_default_region
}

resource "google_compute_address" "natgw" {
  provider = google-beta

  count        = 4
  project      = google_compute_router.this.project
  name         = "natgw-default-${count.index}"
  address_type = "EXTERNAL"
  region       = var.gcp_default_region
}

resource "google_compute_firewall" "ilb_backend" {
  for_each = {
    for key, value in var.ip_addresses.subnetworks : key => value
    if value.purpose == "REGIONAL_MANAGED_PROXY"
  }

  project = local.project_id

  name      = "ilb-backend-${each.key}"
  network   = google_compute_network.this.id
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["443", "80"]
  }

  source_ranges = [
    google_compute_subnetwork.sub[each.key].ip_cidr_range
  ]
}

resource "google_compute_router_nat" "this" {
  project = local.project_id

  name   = "default"
  router = google_compute_router.this.name
  region = google_compute_router.this.region

  enable_dynamic_port_allocation = true

  # NAT rules cannot be added to a NAT gateway that has Endpoint-Independent Mapping enabled. You cannot enable
  # Endpoint-Independent Mapping on a NAT gateway that has NAT rules in it.
  # See https://cloud.google.com/nat/docs/nat-rules-overview#nat-specifications for further details.
  enable_endpoint_independent_mapping = false

  nat_ip_allocate_option = "MANUAL_ONLY"
  nat_ips                = google_compute_address.natgw.*.self_link

  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = false
    filter = "ALL"
  }
}
