/**
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

output "kubernetes_endpoint" {
  sensitive = true
  value     = module.gke.endpoint
}

output "client_token" {
  sensitive = true
  value     = base64encode(data.google_client_config.default.access_token)
}

output "ca_certificate" {
  sensitive = true
  value     = module.gke.ca_certificate
}

output "gke_service_account" {
  description = "The default service account used for running GKE nodes."
  value       = module.gke.service_account
}

output "container_registry_id" {
  description = "The configured container registry ID."
  value       = resource.google_container_registry.registry.id
}

output "github_ci_sa_public_key" {
  sensitive   = true
  description = "The public key for the GitHub actions service account."
  value       = resource.google_service_account_key.github_ci_sa_key.public_key
}

output "github_ci_sa_private_key" {
  sensitive   = true
  description = "The private key for the GitHub actions service account."
  value       = resource.google_service_account_key.github_ci_sa_key.private_key
}

output "jenkins_ci_sa_public_key" {
  sensitive   = true
  description = "The public key for the Jenkins actions service account."
  value       = resource.google_service_account_key.jenkins_ci_sa_key.public_key
}

output "jenkins_ci_sa_private_key" {
  sensitive   = true
  description = "The private key for the Jenkins actions service account."
  value       = resource.google_service_account_key.jenkins_ci_sa_key.private_key
}

output "ctfd_bucket_url" {
  description = "The URL for the CTFd bucket."
  value       = resource.google_storage_bucket.ctfd_bucket.url
}

output "ctfd_bucket_hmac_access_id" {
  sensitive   = true
  description = "The access ID for the CTFd bucket."
  value       = resource.google_storage_hmac_key.ctfd_hmac_key.access_id
}

output "ctfd_bucket_hmac_secret" {
  sensitive   = true
  description = "The secret for the CTFd bucket."
  value       = resource.google_storage_hmac_key.ctfd_hmac_key.secret
}

output "bastion_internal_ip" {
  sensitive   = true
  description = "The internal IP for the bastion."
  value       = google_compute_instance.bastion.network_interface.0.network_ip
}

output "bastion_host_dns" {
  description = "The hostname for the bastion."
  value       = google_dns_record_set.bastion.name
}
