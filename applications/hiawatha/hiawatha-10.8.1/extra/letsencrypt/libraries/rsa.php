<?php
	/* libraries/rsa.php
	 *
	 * Copyright (C) by Hugo Leisink <hugo@leisink.net>
	 * This file is part of the Banshee PHP framework
	 * http://www.banshee-php.org/
	 *
	 * Licensed under The MIT License
	 */

	class RSA {
		private $private_key = null;
		private $public_key = null;
		private $padding = OPENSSL_PKCS1_PADDING;
		private $max_length = null;

		/* Constructor
		 *
		 * INPUT:  string private key PEM (file)[, string passphrase private key, string public key PEM (file)] | integer key size
		 * OUTPUT: -
		 * ERROR:  -
		 */
		public function __construct($private_key, $passphrase = "", $public_key = null) {
			if (is_numeric($private_key)) {
				/* Generate keys
				 */
				$config = array(
					"digest_alg"       => "sha512",
					"private_key_bits" => (int)$private_key,
					"private_key_type" => OPENSSL_KEYTYPE_RSA);

				$this->private_key = openssl_pkey_new($config);

				$details = openssl_pkey_get_details($this->private_key);
				$this->public_key = openssl_pkey_get_public($details["key"]);
			} else {
				/* Load keys
				 */
				$this->fix_path($private_key);
				$this->private_key = openssl_pkey_get_private($private_key, $passphrase);

				if ($public_key === null) {
					$public_key = $private_key;
				} else {
					$this->fix_path($public_key);
				}

				$this->public_key = openssl_pkey_get_public($public_key);
			}

			$details = openssl_pkey_get_details($this->private_key);
			$this->max_length = $details["bits"] / 8;
		}

		/* Fix path of key file
		 */
		private function fix_path(&$key) {
			if (substr($key, 0, 10) == "-----BEGIN") {
				return;
			}

			if (substr($key, 0, 7) == "file://") {
				return;
			}

			$key = "file://".$key;
		}

		/* Magic method get
		 *
		 * INPUT:  string key
		 * OUTPUT: mixed value
		 * ERROR:  null
		 */
		public function __get($key) {
			switch ($key) {
				case "private_key":
					if (openssl_pkey_export($this->private_key, $pem) === false) {
						return false;
					}
					return $pem;
				case "public_key":
					if (($details = openssl_pkey_get_details($this->public_key)) === false) {
						return false;
					}
					return $details["key"];
				case "padding": return $this->padding;
				case "max_length": return $this->max_length;
				case "e":
					$details = openssl_pkey_get_details($this->private_key);
					return $details["rsa"]["e"];
				case "n":
					$details = openssl_pkey_get_details($this->private_key);
					return $details["rsa"]["n"];
			}

			return null;
		}

		/* Magic method set
		 *
		 * INPUT:  string key, mixed value
		 * OUTPUT: -
		 * ERROR:  -
		 */
		public function __set($key, $value) {
			switch ($key) {
				case "padding": $this->padding = $value; break;
			}
		}

		/* Encrypt message with private key
		 *
		 * INPUT:  string message
		 * OUTPUT: string encrypted message
		 * ERROR:  false
		 */
		public function encrypt_with_private_key($message) {
			if ($this->private_key === null) {
				return false;
			} else if (strlen($message) > $this->max_length) {
				return false;
			}
			
			if (openssl_private_encrypt($message, $result, $this->private_key, $this->padding) == false) {
				return false;
			}

			return $result;
		}

		/* Encrypt message with public key
		 *
		 * INPUT:  string message
		 * OUTPUT: string encrypted message
		 * ERROR:  false
		 */
		public function encrypt_with_public_key($message) {
			if ($this->public_key === null) {
				return false;
			} else if (strlen($message) > $this->max_length) {
				return false;
			}
			
			if (openssl_public_encrypt($message, $result, $this->public_key, $this->padding) == false) {
				return false;
			}

			return $result;
		}

		/* Decrypt message with private key
		 *
		 * INPUT:  string message
		 * OUTPUT: string decrypted message
		 * ERROR:  false
		 */
		public function decrypt_with_private_key($message) {
			if ($this->private_key === null) {
				return false;
			} else if (strlen($message) > $this->max_length) {
				return false;
			}
			
			if (openssl_private_decrypt($message, $result, $this->private_key, $this->padding) == false) {
				return false;
			}

			return $result;
		}

		/* Decrypt message with public key
		 *
		 * INPUT:  string message
		 * OUTPUT: string decrypted message
		 * ERROR:  false
		 */
		public function decrypt_with_public_key($message) {
			if ($this->public_key === null) {
				return false;
			} else if (strlen($message) > $this->max_length) {
				return false;
			}
			
			if (openssl_public_decrypt($message, $result, $this->public_key, $this->padding) == false) {
				return false;
			}

			return $result;
		}
	}
?>
