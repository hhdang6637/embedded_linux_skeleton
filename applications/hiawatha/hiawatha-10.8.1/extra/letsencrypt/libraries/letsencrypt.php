<?php
	/* Copyright (c) by Hugo Leisink <hugo@leisink.net>
	 *
	 * This program is free software; you can redistribute it and/or modify
	 * it under the terms of the GNU General Public License as published by
	 * the Free Software Foundation; version 2 of the License. For a copy,
	 * see http://www.gnu.org/licenses/gpl-2.0.html.
	 *
	 * This program is distributed in the hope that it will be useful,
	 * but WITHOUT ANY WARRANTY; without even the implied warranty of
	 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	 * GNU General Public License for more details.
	 */

	class LetsEncrypt {
		const MAX_POLL_DELAY = 5;

		private $account_key = null;
		private $acme = null;
		private $hiawatha = null;

		/* Constructor
		 */
		public function __construct($account_key) {
			$this->account_key = $account_key;
			$this->acme = new ACMEv2(LE_CA_HOSTNAME, $account_key);
			$this->hiawatha = new Hiawatha_config(HIAWATHA_CONFIG_DIR);
		}

		/* Extract CA url from certificate
		 */
		private function get_CA_url($certificate) {
			if (($x509 = openssl_x509_parse($certificate)) == false) {
				return false;
			}

			$ca_info = $x509["extensions"]["authorityInfoAccess"];

			$ca_info = explode("\n", $ca_info);
			foreach ($ca_info as $item) {
				list($label, $info) = explode(" - ", $item);
				if ($label != "CA Issuers") {
					continue;
				}

				list($type, $url) = explode(":", $info, 2);
				if ($type != "URI") {
					return false;
				}

				return $url;
			}

			return false;
		}

		/* Remove hostnames containing a wildcard from the list
		 */
		private function remove_wildcard_hostnames($hostnames) {
			$result = array();

			foreach ($hostnames as $hostname) {
				if (substr($hostname, 0, 2) != "*.") {
					array_push($result, $hostname);
				} else {
					$domain = substr($hostname, 2);
					array_push($result, "www.".$domain);
					array_push($result, $domain);
				}
			}

			return $result;
		}

		/* Remove IP addresses from the list
		 */
		private function remove_ip_addresses($hostnames) {
			$result = array();

			foreach ($hostnames as $hostname) {
				if (filter_var($hostname, FILTER_VALIDATE_IP) == false) {
					array_push($result, $hostname);
				}
			}

			return $result;
		}

		/* Check if certificate is in PEM format
		 */
		private function is_pem_format($cert) {
			return substr($cert, 0, 10) == "-----BEGIN";
		}

		/* Convert certificate in DER format to PEM format
		 */
		private function convert_to_pem($der_cert) {
			$pem_data = chunk_split(base64_encode($der_cert), 64, "\n");
			return "-----BEGIN CERTIFICATE-----\n".$pem_data."-----END CERTIFICATE-----\n";
		}

		/* Get all Hiawatha certificates
		 */
		public function get_certificate_files() {
			return $this->hiawatha->get_certificate_files();
		}

		/* Register account
		 */
		public function register_account($email_address) {
			if (($account_id = $this->acme->register_account($email_address)) === false) {
				printf(" - Account registration failed. Already registered?\n");
				return false;
			} else if ($account_id < 0) {
				$account_id = -$account_id;
				printf(" - Updating account key for ACMI v2 API.\n");
			} else {
				printf(" - Account registered successfully.\n");
			}

			if (($account_key = file_get_contents($this->account_key)) === false) {
				printf("Error reading account key.\n");
				return false;
			}

			chmod($this->account_key, 0600);
			if (($fp = fopen($this->account_key, "w")) != false) {
				fprintf($fp, "ID:%s\n", $account_id);
				fprintf($fp, "%s", $account_key);
				fclose($fp);
			}
			chmod($this->account_key, 0400);

			return true;
		}

		/* Generate Certificate Signing Request
		 */
		private function generate_csr($rsa, $website_hostnames) {
			if (($openssl_config = file_get_contents(__DIR__."/openssl.conf")) == false) {
				printf(" - Error reading OpenSSL configuration template.\n");
				return false;
			}

			$san = implode(", ", array_map(function ($dns) { return "DNS:" . $dns; }, $website_hostnames));
			$openssl_config = str_replace("{SUBJECT_NAME}", $san, $openssl_config);
			$openssl_config = str_replace("{RSA_KEY_SIZE}", CERTIFICATE_RSA_KEY_SIZE, $openssl_config);

			$openssl_config_file = "/tmp/le_openssl_".getmypid().".conf";
			if (file_put_contents($openssl_config_file, $openssl_config) == false) {
				printf("Error writing temporary OpenSSL configuration.\n");
				return false;
			}

			printf("Generating Certificate Signing Request (CSR).\n");
			$dn = array(
				"commonName"             => $website_hostnames[0],
				"emailAddress"           => ACCOUNT_EMAIL_ADDRESS);
			$csr_config = array(
				"digest_alg"             => "sha256",
				"config"                 => $openssl_config_file);
			if (($csr = openssl_csr_new($dn, $rsa->private_key, $csr_config)) === false) {
				printf("OpenSSL %s\n", openssl_error_string());
				return false;
			}
			openssl_csr_export($csr, $csr);
			unlink($openssl_config_file);
			preg_match('~REQUEST-----(.*)-----END~s', $csr, $matches);

			return base64_decode($matches[1]);
		}

		/* Remove challenge files
		 */
		private function remove_challenge_files($website_root) {
			$dir = $website_root."/.well-known/acme-challenge";

			if (($dp = opendir($dir)) === false) {
				return false;
			}

			while (($file = readdir($dp)) !== false) {
				if (substr($file, 0, 1) != ".") {
					unlink($dir."/".$file);
				}
			}
			closedir($dp);

			rmdir($dir);
			rmdir($website_root."/.well-known");

			return true;
		}

		/* Request Let's Encrypt certificate
		 */
		public function request_certificate($website_hostname, $cert_file = null, $reuse_key = false) {
			/* Get website root for hostname
			 */
			if (($website_root = $this->hiawatha->get_website_root($website_hostname)) == null) {
				printf("Hostname %s not found in Hiawatha configuration.\n", $website_hostname);
				return false;
			}

			/* Get all hostnames from Hiawatha configuration
			 */
			$website_hostnames = $this->hiawatha->get_website_hostnames($website_hostname);
			array_unshift($website_hostnames, $website_hostname);
			$website_hostnames = $this->remove_wildcard_hostnames($website_hostnames);
			$website_hostnames = $this->remove_ip_addresses($website_hostnames);

			/* Generate RSA key
			 */
			if ($reuse_key == false) {
				printf("Generating RSA key.\n");
				$rsa = new RSA(CERTIFICATE_RSA_KEY_SIZE);
			} else {
				printf("Loading existing RSA key.\n");
				$rsa = new RSA($cert_file);
			}

			/* Generate CSR
			 */
			if (($csr = $this->generate_csr($rsa, $website_hostnames)) === false) {
				return false;
			}

			/* Order certificate
			 */
			printf("Ordering certificate.\n");
			if (($order = $this->acme->order_certificate($website_hostnames)) == false) {
				return false;
			}

			$dir = $website_root."/.well-known/acme-challenge";
			if (file_exists($dir) == false) {
				if (mkdir($dir, 0755, true) == false) {
					printf(" - Can't create directory %s.\n", $dir);
					return false;
				}
			}

			/* Process order
			 */
			foreach ($order["identifiers"] as $identifier) {
				/* Get authorization challenge
				 */
				printf("Getting authorization challenge for %s.\n", $identifier["value"]);
				if (($challenge = $this->acme->get_challenge($identifier)) == false) {
					printf(" - Error getting challange for %s.\n", $identifier["value"]);
					$this->remove_challenge_files($website_root);
					return false;
				}

				/* Create response for challenge
				 */
				printf(" - Creating reponse for authorization challenge.\n");
				if (file_put_contents($dir."/".$challenge["token"], $challenge["key"]) === false) {
					printf(" - Can't create token %s/%s.\n", $dir, $challenge["token"]);
					$this->remove_challenge_files($website_root);
					return false;
				}

				/* Request authorization
				 */
				printf(" - Requesting authorization for host.\n");
				if ($this->acme->authorize_host($challenge) == false) {
					printf(" - Error authorizing host %s\n", $identifier["value"]);
					$this->remove_challenge_files($website_root);
					return false;
				}

				/* Poll authorization is valid
				 */
				printf(" - Polling authorization status.");
				$timer = self::MAX_POLL_DELAY;
				do {
					if (($result = $this->acme->authorization_valid($identifier)) === true) {
						break;
					}
					printf(".");
					sleep(1);
				} while (--$timer > 0);

				if ($result == false) {
					printf("\n - Polling timed out.\n");
					$this->remove_challenge_files($website_root);
					return false;
				}
				printf("\n");
			}

			/* Finalize order
			 */
			printf("Finalizing order.\n");
			if (($cert_info = $this->acme->finalize_order($order, $csr)) == false) {
				printf(" - Error finalizing order.\n");
				$this->remove_challenge_files($website_root);
				return false;
			}

			/* Remove challenge files
			 */
			printf("Removing challenge responses.\n");
			$this->remove_challenge_files($website_root);

			if ($cert_info["status"] != "valid") {
				/* Poll certificate is ready
				 */
				printf("Polling certificate readiness.");
				$timer = self::MAX_POLL_DELAY;
				do {
					if (($result = $this->acme->certificate_ready($cert_info["location"])) === true) {
						break;
					}
					printf(".");
					sleep(1);
				} while (--$timer > 0);

				if ($result == false) {
					printf("\n - Polling timed out.\n");
					$this->remove_challenge_files($website_root);
					return false;
				}
				printf("\n");
			}

			/* Download certificates
			 */
			printf("Downloading certificates.\n");
			if (($certificate = $this->acme->get_certificate($cert_info["download"])) == false) {
				printf(" - Error downloading certificate.\n");
				return false;
			}

			if ($this->is_pem_format($certificate) == false) {
				$certificate = $this->convert_to_pem($certificate);
			}

			$certificate = str_replace("\r", "", $certificate);

			/* Write certificates
			 */
			if ($cert_file == null) {
				$dir = (posix_getuid() == 0) ? HIAWATHA_CERT_DIR."/" : "";
				$cert_file = $dir.$website_hostname.".pem";
				$number = 1;
				while (file_exists($cert_file)) {
					$cert_file = $dir.$website_hostname."-".$number.".pem";
					$number++;
				}
				printf("Using %s as output file.\n", $cert_file);
			} else {
				chmod($cert_file, 0600);
			}

			if (($fp = fopen($cert_file, "w")) == false) {
				printf("\n%s\n%s\n", $rsa->private_key, $certificate);
			} else {
				printf("Writing private key and certificates to file.\n");
				fputs($fp, $rsa->private_key."\n");
				fputs($fp, $certificate."\n");
				fclose($fp);
				chmod($cert_file, 0600);
			}

			printf("\n");

			return true;
		}

		/* Revoke Let's Encrypt certificate
		 */
		public function revoke_certificate($cert_file) {
			if (($cert = file_get_contents($cert_file)) == false) {
				printf(" - Certificate file %s not found.\n", $cert_file);
				return false;
			}

			preg_match('~BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE~s', $cert, $matches);
			if (($cert = $matches[1]) == null) {
				printf(" - Invalid certificate file.\n");
			}
			$cert = base64_decode($cert, true);

			if ($this->acme->revoke_certificate($cert)) {
				printf("Certificate revoked successfully.\n");
			}

			return true;
		}
	}
?>
