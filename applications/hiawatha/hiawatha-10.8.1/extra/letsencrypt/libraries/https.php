<?php
	/* libraries/https.php
	 *
	 * Copyright (C) by Hugo Leisink <hugo@leisink.net>
	 * This file is part of the Banshee PHP framework
	 * http://www.banshee-php.org/
	 *
	 * Licensed under The MIT License
	 */

	class HTTPS extends HTTP {
		protected $default_port = 443;
		protected $protocol = "tls";
	}
?>
