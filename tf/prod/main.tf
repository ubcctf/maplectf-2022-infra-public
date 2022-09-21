data "google_client_config" "default" {}

// Service Accounts

resource "google_service_account" "gke_sa" {
  account_id   = "gke-${var.cluster_name}"
  display_name = "MapleCTF GKE SA"
  description  = "MapleCTF GKE Service Account"
  project      = var.project_id
}

resource "google_service_account" "external_dns_sa" {
  account_id   = "gke-external-dns-${var.cluster_name}"
  display_name = "MapleCTF external-dns SA"
  description  = "MapleCTF external-dns Service Account"
  project      = var.project_id
}

resource "google_service_account" "github_ci_sa" {
  account_id   = "github-ci"
  display_name = "MapleCTF Github Actions SA"
  description  = "MapleCTF Github Actions Service Account"
  project      = var.project_id
}

resource "google_service_account" "gcp_compute_sa" {
  account_id   = "gcp-compute"
  display_name = "MapleCTF Compute SA"
  description  = "MapleCTF Compute Service Account"
  project      = var.project_id
}

resource "google_service_account" "jenkins_ci_sa" {
  account_id   = "jenkins-ci"
  display_name = "MapleCTF Jenkins SA"
  description  = "MapleCTF Jenkins Service Account"
  project      = var.project_id
}

resource "google_service_account" "ctfd_sa" {
  account_id   = "ctfd-storage"
  display_name = "MapleCTF CTFd SA"
  description  = "MapleCTF CTFd Service Account"
  project      = var.project_id
}

// Service Account Keys

resource "google_service_account_key" "github_ci_sa_key" {
  service_account_id = google_service_account.github_ci_sa.name
  public_key_type    = "TYPE_X509_PEM_FILE"
  private_key_type   = "TYPE_GOOGLE_CREDENTIALS_FILE"
}

resource "google_service_account_key" "jenkins_ci_sa_key" {
  service_account_id = google_service_account.jenkins_ci_sa.name
  public_key_type    = "TYPE_X509_PEM_FILE"
  private_key_type   = "TYPE_GOOGLE_CREDENTIALS_FILE"
}

// IAM bindings

resource "google_project_iam_binding" "sa_admin_project_iam_binding" {
  project = var.project_id
  role    = "roles/iam.serviceAccountAdmin"

  members = [
    "serviceAccount:${google_service_account.gke_sa.email}",
    "serviceAccount:${google_service_account.github_ci_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_iam_binding" {
  project = var.project_id
  role    = "roles/iam.securityAdmin"

  members = [
    "serviceAccount:${google_service_account.github_ci_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_iam_sak_binding" {
  project = var.project_id
  role    = "roles/iam.serviceAccountKeyAdmin"

  members = [
    "serviceAccount:${google_service_account.github_ci_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_iam_sa_user_binding" {
  project = var.project_id
  role    = "roles/iam.serviceAccountUser"

  members = [
    "serviceAccount:${google_service_account.gke_sa.email}",
    "serviceAccount:${google_service_account.github_ci_sa.email}",
    "serviceAccount:${google_service_account.gcp_compute_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_container_admin_binding" {
  project = var.project_id
  role    = "roles/container.admin"

  members = [
    "serviceAccount:${google_service_account.github_ci_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_container_viewer_binding" {
  project = var.project_id
  role    = "roles/container.viewer"

  members = [
    "serviceAccount:${google_service_account.gcp_compute_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_storage_admin_binding" {
  project = var.project_id
  role    = "roles/storage.admin"

  members = [
    "serviceAccount:${google_service_account.github_ci_sa.email}",
    "serviceAccount:${google_service_account.jenkins_ci_sa.email}",
    "serviceAccount:${google_service_account.ctfd_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_storage_object_viewer_binding" {
  project = var.project_id
  role    = "roles/storage.objectViewer"

  members = [
    "serviceAccount:${google_service_account.gke_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_storage_hmac_binding" {
  project = var.project_id
  role    = "roles/storage.hmacKeyAdmin"

  members = [
    "serviceAccount:${google_service_account.github_ci_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_dns_binding" {
  project = var.project_id
  role    = "roles/dns.admin"

  members = [
    "serviceAccount:${google_service_account.github_ci_sa.email}",
    "serviceAccount:${google_service_account.external_dns_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_compute_binding" {
  project = var.project_id
  role    = "roles/compute.admin"

  members = [
    "serviceAccount:${google_service_account.github_ci_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_compute_instance_admin_binding" {
  project = var.project_id
  role    = "roles/compute.instanceAdmin"

  members = [
    "serviceAccount:${google_service_account.gcp_compute_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_os_login_binding" {
  project = var.project_id
  role    = "roles/compute.osLogin"

  members = [
    "serviceAccount:${google_service_account.gcp_compute_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_monitoring_admin" {
  project = var.project_id
  role    = "roles/monitoring.admin"

  members = [
    "serviceAccount:${google_service_account.gke_sa.email}",
  ]
}

resource "google_project_iam_binding" "sa_project_logging_admin" {
  project = var.project_id
  role    = "roles/logging.admin"

  members = [
    "serviceAccount:${google_service_account.gke_sa.email}",
  ]
}

// VPC

resource "google_compute_network" "vpc_network" {
  name                    = "${var.cluster_name}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "gke_subnet" {
  name                     = "${var.cluster_name}-subnet"
  project                  = var.project_id
  region                   = var.region
  ip_cidr_range            = "10.5.0.0/16"
  network                  = google_compute_network.vpc_network.name
  private_ip_google_access = true

  secondary_ip_range = [
    {
      range_name    = "${var.cluster_name}-pod-subnet"
      ip_cidr_range = "10.6.0.0/16"
    },
    {
      range_name    = "${var.cluster_name}-services-subnet"
      ip_cidr_range = "10.7.0.0/16"
    },
  ]
}

resource "google_compute_network" "public_vpc_network" {
  name                    = "${var.project_id}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "public_vpc_subnet" {
  name                     = "${google_compute_network.public_vpc_network.name}-subnet"
  project                  = var.project_id
  region                   = var.region
  ip_cidr_range            = "10.0.0.0/24"
  network                  = google_compute_network.public_vpc_network.name
  private_ip_google_access = true
}

resource "google_compute_router" "gke_router" {
  name    = "${var.cluster_name}-router"
  project = var.project_id
  region  = google_compute_subnetwork.gke_subnet.region
  network = google_compute_network.vpc_network.id
}

resource "google_compute_router_nat" "gke_nat_gateway" {
  name                               = "${var.cluster_name}-nat-gateway"
  project                            = var.project_id
  router                             = google_compute_router.gke_router.name
  region                             = google_compute_router.gke_router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

resource "google_compute_network_peering" "gke_to_public_peering" {
  name         = "gke-to-public"
  network      = google_compute_network.vpc_network.self_link
  peer_network = google_compute_network.public_vpc_network.self_link
}

resource "google_compute_network_peering" "public_to_gke_peering" {
  name         = "public-to-gke"
  network      = google_compute_network.public_vpc_network.self_link
  peer_network = google_compute_network.vpc_network.self_link
}

// Firewall

resource "google_compute_firewall" "public_vpc_allow_icmp" {
  name        = "${google_compute_network.public_vpc_network.name}-allow-icmp"
  project     = var.project_id
  network     = google_compute_network.public_vpc_network.name
  description = "Allow ICMP"

  direction = "INGRESS"

  allow {
    protocol = "icmp"
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "public_vpc_allow_ssh" {
  name        = "${google_compute_network.public_vpc_network.name}-allow-ssh"
  project     = var.project_id
  network     = google_compute_network.public_vpc_network.name
  description = "Allow SSH"

  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "public_vpc_allow_internal" {
  name        = "${google_compute_network.public_vpc_network.name}-allow-internal"
  project     = var.project_id
  network     = google_compute_network.public_vpc_network.name
  description = "Allow internal traffic"

  direction = "INGRESS"

  allow {
    protocol = "all"
  }

  source_ranges = ["10.0.0.0/24"]
}

resource "google_compute_firewall" "gke_to_public_peering_allow_all" {
  name        = "${google_compute_network.vpc_network.name}-allow-public"
  project     = var.project_id
  network     = google_compute_network.vpc_network.name
  description = "Allow traffic from public"

  direction = "INGRESS"

  allow {
    protocol = "all"
  }

  source_ranges = [google_compute_subnetwork.public_vpc_subnet.ip_cidr_range]
}

resource "google_compute_firewall" "public_to_gke_peering_allow_all" {
  name        = "${google_compute_network.public_vpc_network.name}-allow-gke"
  project     = var.project_id
  network     = google_compute_network.public_vpc_network.name
  description = "Allow traffic from GKE"

  direction = "INGRESS"

  allow {
    protocol = "all"
  }

  source_ranges = [google_compute_subnetwork.gke_subnet.ip_cidr_range]
}

// Cloud Armor 

resource "google_compute_security_policy" "admin-whitelist" {
  name    = "admin-whitelist"
  project = var.project_id

  rule {
    action   = "allow"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["123.456.789.0/32"]
      }
    }
    description = "IP Whitelist"
  }

  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }
}

// Compute Engine (GCE)

resource "google_compute_instance" "bastion" {
  name         = "bastion"
  project      = var.project_id
  machine_type = "e2-highcpu-2"
  zone         = var.zone

  allow_stopping_for_update = true

  tags = ["bastion", "dockerd"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  metadata = {
    "ssh-keys" = <<EOF
jenkins:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN1qrbRO6ma8kgn5EsPyGSCdJuA7J3AXs3Ve/scoazwd jenkins-maplectf
EOF
  }

  network_interface {
    network    = google_compute_network.public_vpc_network.name
    subnetwork = google_compute_subnetwork.public_vpc_subnet.name

    access_config {
      // Ephemeral public IP
    }
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.gcp_compute_sa.email
    scopes = ["cloud-platform"]
  }
}

// Kubernetes (GKE)

provider "kubernetes" {
  host                   = "https://${module.gke.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(module.gke.ca_certificate)
}

module "gke" {
  source     = "terraform-google-modules/kubernetes-engine/google//modules/private-cluster"
  version    = "22.1.0"
  project_id = var.project_id
  name       = var.cluster_name
  regional   = false
  region     = var.region
  zones      = var.zones

  network                 = google_compute_network.vpc_network.name
  subnetwork              = google_compute_subnetwork.gke_subnet.name
  ip_range_pods           = google_compute_subnetwork.gke_subnet.secondary_ip_range[0].range_name
  ip_range_services       = google_compute_subnetwork.gke_subnet.secondary_ip_range[1].range_name
  enable_private_endpoint = false
  enable_private_nodes    = true
  master_ipv4_cidr_block  = "172.16.5.0/28"
  datapath_provider       = "ADVANCED_DATAPATH"

  create_service_account = false
  service_account        = google_service_account.gke_sa.email

  horizontal_pod_autoscaling = true
  default_max_pods_per_node  = 100
  remove_default_node_pool   = true
  initial_node_count         = 1
  cluster_autoscaling = {
    enabled       = true
    gpu_resources = []
    max_cpu_cores = 512
    max_memory_gb = 512
    min_cpu_cores = 8
    min_memory_gb = 16
  }

  master_authorized_networks = [
    {
      cidr_block   = google_compute_subnetwork.gke_subnet.ip_cidr_range
      display_name = "${var.cluster_name}-subnet"
    },
    {
      cidr_block   = "${google_compute_instance.bastion.network_interface[0].access_config[0].nat_ip}/32"
      display_name = "bastion"
    },
    {
      cidr_block   = "${google_compute_instance.bastion.network_interface[0].network_ip}/32"
      display_name = "bastion-internal"
    },
  ]

  node_pools = [
    {
      name            = "ctfd-node-pool"
      machine_type    = "e2-highcpu-32"
      min_count       = 1
      max_count       = 3
      local_ssd_count = 0
      spot            = false
      disk_size_gb    = 25
      disk_type       = "pd-balanced"
      image_type      = "COS_CONTAINERD"
      autoscaling     = true
      auto_repair     = true
      auto_upgrade    = true
      service_account = google_service_account.gke_sa.email
    },
    {
      name            = "maplectf-node-pool"
      machine_type    = "e2-highcpu-16"
      min_count       = 1
      max_count       = 20
      local_ssd_count = 0
      spot            = false
      disk_size_gb    = 50
      disk_type       = "pd-balanced"
      image_type      = "COS_CONTAINERD"
      autoscaling     = true
      auto_repair     = true
      auto_upgrade    = true
      service_account = google_service_account.gke_sa.email
    }
  ]

  node_pools_oauth_scopes = {
    all = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]
  }

  node_pools_labels = {
    all = {}

    ctfd-node-pool = {
      ctfd-only = true
    }
  }

  node_pools_taints = {
    all = []

    ctfd-node-pool = [
      {
        key    = "ctfd-node-pool"
        value  = true
        effect = "NO_SCHEDULE"
      },
    ]
  }
}

// DNS

resource "google_dns_managed_zone" "maplectf-zone" {
  name        = "maplectf-zone"
  project     = var.project_id
  dns_name    = "ctf.maplebacon.org."
  description = "maplectf zone"
  labels = {
    maplectf = "maplectf"
  }
}

resource "google_dns_managed_zone" "maplectf-internal-zone" {
  name        = "maplectf-internal-zone"
  project     = var.project_id
  dns_name    = "internal.ctf.maplebacon.org."
  description = "maplectf internal zone"
  visibility  = "private"
  labels = {
    maplectf = "maplectf"
  }

  private_visibility_config {
    networks {
      network_url = google_compute_network.vpc_network.id
    }
    networks {
      network_url = google_compute_network.public_vpc_network.id
    }
  }
}

resource "google_dns_record_set" "bastion" {
  name         = "bastion.${google_dns_managed_zone.maplectf-zone.dns_name}"
  managed_zone = google_dns_managed_zone.maplectf-zone.name
  project      = var.project_id
  type         = "A"
  ttl          = 300

  rrdatas = [google_compute_instance.bastion.network_interface[0].access_config[0].nat_ip]
}

resource "google_dns_record_set" "artgallery" {
  name         = "artgallery.${google_dns_managed_zone.maplectf-zone.dns_name}"
  managed_zone = google_dns_managed_zone.maplectf-zone.name
  project      = var.project_id
  type         = "A"
  ttl          = 300

  rrdatas = ["159.223.138.254"]
}

resource "google_dns_record_set" "bastion-internal" {
  name         = "bastion.${google_dns_managed_zone.maplectf-internal-zone.dns_name}"
  managed_zone = google_dns_managed_zone.maplectf-internal-zone.name
  project      = var.project_id
  type         = "A"
  ttl          = 300

  rrdatas = [google_compute_instance.bastion.network_interface[0].network_ip]
}

resource "google_dns_record_set" "mailgun-spf" {
  name         = google_dns_managed_zone.maplectf-zone.dns_name
  managed_zone = google_dns_managed_zone.maplectf-zone.name
  project      = var.project_id
  type         = "TXT"
  ttl          = 300

  rrdatas = ["\"v=spf1 include:mailgun.org ~all\""]
}

resource "google_dns_record_set" "mailgun-dkim" {
  name         = "smtp._domainkey.${google_dns_managed_zone.maplectf-zone.dns_name}"
  managed_zone = google_dns_managed_zone.maplectf-zone.name
  project      = var.project_id
  type         = "TXT"
  ttl          = 300

  rrdatas = ["\"k=rsa; p=REDACTED\" \"REDACTED\""]
}

resource "google_dns_record_set" "mailgun-mx" {
  name         = google_dns_managed_zone.maplectf-zone.dns_name
  managed_zone = google_dns_managed_zone.maplectf-zone.name
  project      = var.project_id
  type         = "MX"
  ttl          = 300

  rrdatas = [
    "10 mxa.mailgun.org.",
  "10 mxb.mailgun.org.", ]
}

resource "google_dns_record_set" "mailgun-cname" {
  name         = "email.${google_dns_managed_zone.maplectf-zone.dns_name}"
  managed_zone = google_dns_managed_zone.maplectf-zone.name
  project      = var.project_id
  type         = "CNAME"
  ttl          = 300

  rrdatas = ["mailgun.org."]
}

// Container Registry (GCR)

resource "google_container_registry" "registry" {
  project  = var.project_id
  location = "US"
}

// Storage Buckets (GCS)

resource "google_storage_bucket" "ctfd_bucket" {
  name          = "ctfd-maplectf"
  project       = var.project_id
  location      = "US"
  force_destroy = true
}

// Storage Buckets (GCS) Keys

resource "google_storage_hmac_key" "ctfd_hmac_key" {
  project               = var.project_id
  service_account_email = google_service_account.ctfd_sa.email
}
