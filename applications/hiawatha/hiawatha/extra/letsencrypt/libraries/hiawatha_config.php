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

	class Hiawatha_config {
		private $website_root = array();
		private $website_hostnames = array();
		private $certificate_files = array();

		public function __construct($config_dir) {
			if (($dp = opendir(HIAWATHA_CERT_DIR)) != false) {
				while (($file = readdir($dp)) !== false) {
					if (substr($file, 0, 1) == ".") {
						continue;
					}

					if (substr($file, 0, 1) != "/") {
						$file = HIAWATHA_CERT_DIR."/".$file;
					}

					if (is_file($file) == false) {
						continue;
					}

					array_push($this->certificate_files, $file);
				}
				sort($this->certificate_files);

				closedir($dp);
			}

			$this->read_config_file($config_dir."/hiawatha.conf");
		}

		public function get_website_root($hostname) {
			return $this->website_root[$hostname];
		}

		public function get_website_hostnames($hostname) {
			return $this->website_hostnames[$hostname];
		}

		public function get_certificate_files() {
			return $this->certificate_files;
		}

		private function read_config_dir($config_dir) {
			if (($dp = opendir($config_dir)) === false) {
				printf(" - Can't find config directory %s.\n", $config_dir);
				return false;
			}

			while (($file = readdir($dp)) !== false) {
				if (substr($file, 0, 1) == ".") {
					continue;
				}

				$this->read_config_file($config_dir."/".$file);
			}

			closedir($dp);

			return true;
		}

		private function read_config_file($config_file) {
			if (($fp = fopen($config_file, "r")) === false) {
				printf(" - Can't find config file %s.\n", $config_file);
				return false;
			}

			$inside_virtual_host = false;
			while (($line = fgets($fp)) !== false) {
				list($command, $param) = explode(" ", trim($line), 2);
				$command = strtolower($command);
				$param = trim($param, " =");

				if ($inside_virtual_host) {
					if ($command == "hostname") {
						$hostnames = explode(",", strtolower($param));
						foreach ($hostnames as $key => $value) {
							$hostnames[$key] = trim($value);
						}
						if ($hostname == null) {
							$hostname = array_shift($hostnames);
							$this->website_hostnames[$hostname] = $hostnames;
						} else {
							$this->website_hostnames[$hostname] = array_merge($this->website_hostnames[$hostname], $hostnames);
						}
					} else if ($command == "websiteroot") {
						$websiteroot = $param;
					} else if ($command == "tlscertfile") {
						if (substr($param, 0, 1) != "/") {
							$param = HIAWATHA_CONFIG_DIR."/".$param;
						}
						if (in_array($param, $this->certificate_files) == false) {
							array_push($this->certificate_files, $param);
							sort($this->certificate_files);
						}
					} else if ($command == "}") {
						if (($hostname != null) && ($websiteroot != null)) {
							$this->website_root[$hostname] = $websiteroot;
						}
						$hostname = $websiteroot = null;
						$inside_virtual_host = false;
					}
				} else if ($command == "virtualhost") {
					$inside_virtual_host = true;
				} else if ($command == "include") {
					if (substr($param, 0, 1) != "/") {
						if (($last_slash = strrpos($config_file, "/")) !== false) {
							$config_dir = substr($config_file, 0, $last_slash + 1);
							$param = $config_dir.$param;
						}
					}

					if (is_dir($param)) {
						$this->read_config_dir($param);
					} else {
						$this->read_config_file($param);
					}
				}
			}

			fclose($fp);

			return true;
		}
	}
?>
