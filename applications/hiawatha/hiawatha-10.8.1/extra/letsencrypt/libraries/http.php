<?php
	/* libraries/http.php
	 *
	 * Copyright (C) by Hugo Leisink <hugo@leisink.net>
	 * This file is part of the Banshee PHP framework
	 * http://www.banshee-php.org/
	 *
	 * Licensed under The MIT License
	 */

	class HTTP {
		protected $host = null;
		protected $port = null;
		protected $headers = array();
		protected $cookies = array();
		protected $proxy_type = null;
		protected $proxy_tls = false;
		protected $connect_host = null;
		protected $connect_port = null;
		protected $default_port = 80;
		protected $protocol = "tcp";
		protected $timeout = 5;
		protected $username = null;
		protected $password = null;
		protected $authorization = null;

		/* Constructor
		 *
		 * INPUT:  string host[, int port]
		 * OUTPUT: -
		 * ERROR:  -
		 */
		public function __construct($host, $port = null) {
			if ($port === null) {
				$port = $this->default_port;
			}

			$this->host = $this->connect_host = $host;
			$this->port = $this->connect_port = $port;
		}

		/* Magic method get
		 *
		 * INPUT:  string key
		 * OUTPUT: mixed value
		 * ERROR:  null
		 */
		public function __get($key) {
			switch ($key) {
				case "cookies": return $this->cookies;
			}

			return null;
		}

		/* Magic method call
		 *
		 * INPUT:  string method, string URI[, string body]
		 * OUTPUT: array request result
		 * ERROR:  false
		 */
		public function __call($method, $parameters) {
			list($uri, $body) = $parameters;

			$methods = array("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE");
			if (in_array($method, $methods) == false) {
				return false;
			}

			/* Method specific actions
			 */
			switch ($method) {
				case "POST":
					if (is_array($body)) {
						foreach ($body as $key => $value) {
							$body[$key] = urlencode($key)."=".urlencode($value);
						}
						$body = implode("&", $body);

						$this->add_header("Content-Type", "application/x-www-form-urlencoded");
					} else {
						$this->add_header("Content-Type", "application/octet-stream", false);
					}

					$this->add_header("Content-Length", strlen($body));
					break;
				case "PUT":
					if (is_array($body)) {
						$body = implode("", $body);
					}
					$this->add_header("Content-Length", strlen($body));
					break;
				default:
					$body = "";
			}

			/* Add HTTP headers
			 */
			$this->add_header("Host", $this->host);
			$this->add_header("Accept", "*/*");
			$this->add_header("Accept-Charset", "ISO-8859-1,utf-8");
			$this->add_header("Accept-Language", "en-US");
			$this->add_header("Connection", "close");
			$this->add_header("User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)");
			if (function_exists("gzdecode")) {
				$this->add_header("Accept-Encoding", "gzip");
			}
			if ($this->authorization !== null) {
				$this->add_header("Authorization", $this->authorization);
			}

			/* Add cookies
			 */
			$cookies = array();
			foreach ($this->cookies as $key => $value) {
				array_push($cookies, $key."=".$value);
			}
			if (count($cookies) > 0) {
				$this->add_header("Cookie", implode("; ", $cookies));
			}

			/* Perform request
			 */
			if (($result = $this->perform_request($method, $uri, $body)) !== false) {
				if (($result = $this->parse_request_result($result)) !== false) {
					/* Apply authentication
					 */
					if ($result["status"] == 401) {
						if ($this->apply_authentication($method, $uri, $result)) {
							if (($result = $this->perform_request($method, $uri, $body)) !== false) {
								$result = $this->parse_request_result($result);
							}
						}
					}
				}
			}

			$this->headers = array();

			return $result;
		}

		/* Send request via HTTP proxy
		 *
		 * INPUT:  string host, int port[, bool tls]
		 * OUTPUT: -
		 * ERROR:  -
		 */
		public function via_HTTP_proxy($host, $port, $tls = false) {
			$this->connect_host = $host;
			$this->connect_port = $port;
			$this->protocol = $tls ? "tls" : "tcp";
			$this->proxy_type = "http";
			$this->proxy_tls = $tls;
		}

		/* Send request via SOCKS proxy
		 *
		 * INPUT:  string host, int port[, bool tls]
		 * OUTPUT: -
		 * ERROR:  -
		 */
		public function via_SOCKS_proxy($host, $port, $tls = false) {
			$this->connect_host = $host;
			$this->connect_port = $port;
			$this->protocol = $tls ? "tls" : "tcp";
			$this->proxy_type = "socks";
			$this->proxy_tls = $tls;
		}

		/* Set credentials for HTTP authentication
		 *
		 * INPUT:  string username, string password
		 * OUTPUT: -
		 * ERROR:  -
		 */
		public function set_credentials($username, $password) {
			$this->username = $username;
			$this->password = $password;
			$this->authorization = null;
		}

		/* Add HTTP header
		 *
		 * INPUT:  string key, string value,[ bool replace header]
		 * OUTPUT: -
		 * ERROR:  -
		 */
		public function add_header($key, $value, $replace = true) {
			if ($replace || (isset($this->headers[$key]) == false)) {
				$this->headers[$key] = $key.": ".$value;
			}
		}

		/* Add cookie
		 *
		 * INPUT:  string key, string value
		 * OUTPUT: -
		 * ERROR:  -
		 */
		public function add_cookie($key, $value) {
			if ($key != "") {
				$this->cookies[$key] = $value;
			}
		}

		/* Simulate AJAX for next request
		 *
		 * INPUT:  -
		 * OUTPUT: -
		 * ERROR:  -
		 */
		public function simulate_ajax_request() {
			$this->add_header("X-Requested-With", "XMLHttpRequest");
		}

		/* Connect to server
		 *
		 * INPUT:  -
		 * OUTPUT: resource socket
		 * ERROR:  false connection failed
		 */
		protected function connect_to_server() {
			$protocol = (($this->proxy_type == "socks") && $this->proxy_tls) ? "tls" : "tcp";

			$context = stream_context_create();
			if ($protocol == "tls") {
				if (stream_context_set_option($context, "ssl", "verify_peer", true) == false) {
					return false;
				#} else if (stream_context_set_option($context, "ssl", "ca_file", "/etc/ssl/certs/ca-certificates.crt") == false) {
				#	return false;
				}
			}

			$remote = sprintf("%s://%s:%s", $protocol, $this->connect_host, $this->connect_port);
			if (($sock = @stream_socket_client($remote, $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $context)) === false) {
				return false;
			}

			if ($this->proxy_type == "socks") {
				/* Perform SOCKS handshake
				 */
				if (fputs($sock, pack("C3", 0x05, 0x01, 0x00)) === false) {
					return false;
				} else if (($line = fread($sock, 16)) === false) {
					return false;
				} else if ($line != pack("C2", 0x05, 0x00)) {
					return false;
				}

				$data = pack("C5", 0x05 , 0x01 , 0x00 , 0x03, strlen($this->host)).$this->host.pack("n", $this->port);
				if (fputs($sock, $data) === false) {
					return false;
				} else if (($line = fread($sock, 16)) === false) {
					return false;
				} else if ($line != pack("C10", 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) {
					return false;
				}
			}

			/* Enable TLS encryption
			 */
			if ($this->default_port == 80) {
				if (($this->proxy_type == "http") && $this->proxy_tls) {
					$enable_crypto = true;
				} else {
					$enable_crypto = false;
				}
			} else {
				if (($this->proxy_type == "http") && ($this->proxy_tls == false)) {
					$enable_crypto = false;
				} else {
					$enable_crypto = true;
				}
			}

			if ($enable_crypto) {
				if (stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT) == false) {
					return false;
				}
			}

			return $sock;
		}

		/* Perform HTTP request
		 *
		 * INPUT:  string method, string uri[, string request body]
		 * OUTPUT: array( "status" => string status, "headers" => array HTTP headers, "body" => request body )
		 * ERROR:  false
		 */
		protected function perform_request($method, $url, $body = "") {
			if (($sock = $this->connect_to_server()) == false) {
				return false;
			}

			/* Connect via proxy
			 */
			if ($this->proxy_type == "http") {
				/* Add host and port to URL
				 */
				$protocol = $this->default_port == 80 ? "http" : "https";
				$port = $this->port != $this->default_port ? ":".$this->port : "";
				$url = sprintf("%s://%s%s%s", $protocol, $this->host, $port, $url);
			}

			/* Build and send request
			 */
			$headers = implode("\r\n", $this->headers);
			$request = sprintf("%s %s HTTP/1.1\r\n%s\r\n\r\n%s", $method, $url, $headers, $body);
			if (fputs($sock, $request) === false) {
				return false;
			}

			/* Read response
			 */
			$result = "";
			while (($line = fgets($sock)) !== false) {
				$result .= $line;
			}

			fclose($sock);

			return $result;
		}

		/* Parse request result
		 *
		 * INPUT:  string result
		 * OUTPUT: array result
		 * ERROR:  -
		 */
		protected function parse_request_result($result) {
			list($header, $body) = explode("\r\n\r\n", $result, 2);
			$header = explode("\r\n", $header);
			list(, $status) = explode(" ", $header[0]);

			$result = array(
				"status"  => (int)$status,
				"headers" => array(),
				"body"    => $body);

			/* Parse response headers
			 */
			$gzdecode = false;
			for ($i = 1; $i < count($header); $i++) {
				$parts = explode(":", $header[$i], 2);
				list($key, $value) = array_map("trim", $parts);
				$key = strtolower($key);
				$result["headers"][$key] = $value;

				if ($key == "set-cookie") {
					/* Cookie
					 */
					list($value) = explode(";", $value);
					list($cookie_key, $cookie_value) = explode("=", $value);
					$this->add_cookie($cookie_key, $cookie_value);
				} else if ($key == "content-encoding") {
					/* Content encoding
					 */
					if (strpos($value, "gzip") !== false) {
						$gzdecode = true;
					}
				} else if ($key == "transfer-encoding") {
					/* Transfer encoding
					 */
					if (strpos($value, "chunked") !== false) {
						$data = $result["body"];
						$result["body"] = "";

						do {
							list($size, $data) = explode("\r\n", $data, 2);
							$size = hexdec($size);
							if ($size > 0) {
								$chunk = substr($data, 0, $size);
								if (substr($data, $size, 2) != "\r\n") {
									$result["body"] = "";
									break;
								}
								$data = substr($data, $size + 2);
								$result["body"] .= $chunk;
							} else {
								break;
							}
						} while (strlen($data) > 0);
					}
				}
			}

			/* GZip content encoding
			 */
			if ($gzdecode) {
				if (($result["body"] = @gzdecode($result["body"])) === false) {
					return false;
				}
			}

			return $result;
		}

		/* Apply authentication to request
		 *
		 * INPUT:  string HTTP method, string URI, array request result
		 * OUTPUT: true
		 * ERROR:  false
		 */
		private function apply_authentication($method, $uri, $result) {
			if (($this->username == null) || ($this->password == null)) {
				return false;
			}

			if (($www_auth = $result["headers"]["www-authenticate"]) == null) {
				return false;
			}
			list($type, $parameters) = explode(" ", $www_auth, 2);

			if ($type == "Basic") {
				/* Basic HTTP authentication
				 */
				$auth = base64_encode($this->username.":".$this->password);
				$this->authorization = "Basic ".$auth;
			} else if ($type == "Digest") {
				/* Digest HTTP authentication
				 */
				$digest = array();
				$parameters = explode(",", $parameters);
				foreach ($parameters as $parameter) {
					list($key, $value) = explode("=", $parameter, 2);
					$digest[trim($key)] = trim(trim($value), '"');
				}

				$ha1 = md5($this->username.":".$digest["realm"].":".$this->password);
				$ha2 = md5($method.":".$uri);
				$response = md5($ha1.":".$digest["nonce"].":".$ha2);

				$format = 'username="%s",realm="%s",nonce="%s",uri="%s",response="%s",opaque="%s"';
				$auth = sprintf($format, $this->username, $digest["realm"], $digest["nonce"], $uri, $response, $digest["opaque"]);
				$this->authorization = "Digest ".$auth;
			} else {
				return false;
			}

			$this->add_header("Authorization", $this->authorization);

			return true;
		}
	}
?>
