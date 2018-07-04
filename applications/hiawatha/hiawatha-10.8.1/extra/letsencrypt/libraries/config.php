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

	class config {
		const CONFIG_FILE = "letsencrypt.conf";
		private $config = array();

		/* Constructor
		 */
		public function __construct($locations) {
			if (($config_dir = $this->find_config_dir($locations)) == false) {
				return;
			}

			$config_file = $config_dir."/".self::CONFIG_FILE;
			$this->config["ACCOUNT_KEY_FILE"] = $config_dir."/account.key";

			/* Read configuration file
			 */
			$config = array();
			foreach (file($config_file) as $line) {
				$line = trim(preg_replace("/(^|\s)#.*/", "", $line));
				$line = rtrim($line);

				if ($line === "") {
					continue;
				}

				if (($prev = count($config) - 1) == -1) {
					array_push($config, $line);
				} else if (substr($config[$prev], -1) == "\\") {
					$config[$prev] = rtrim(substr($config[$prev], 0, strlen($config[$prev]) - 1)) . "|" . ltrim($line);
				} else {
					array_push($config, $line);
				}
			}

			/* Expand keys in values
			 */
			foreach ($config as $line) {
				list($key, $value) = explode("=", chop($line), 2);
				$key = trim($key);
				$value = trim($value);

				foreach ($this->config as $k => $v) {
					$value = str_replace("{".$k."}", $v, $value);
				}

				$this->config[$key] = $value;
			}

			/* Script directory
			 */
			if (substr($this->config["RENEWAL_SCRIPT_DIR"], 0, 1) != "/") {
				$this->config["RENEWAL_SCRIPT_DIR"] = $config_dir."/".$this->config["RENEWAL_SCRIPT_DIR"];
			}
		}

		/* Magic method get
		 */
		public function __get($key) {
			switch ($key) {
				case "content": return $this->config;
			}

			return null;
		}

		/* Find configuration directory
		 */
		private function find_config_dir($locations) {
			foreach ($locations as $location) {
				$file = $location."/".self::CONFIG_FILE;
				if (file_exists($file)) {
					return $location;
				}
			}

			return false;
		}
	}
?>
