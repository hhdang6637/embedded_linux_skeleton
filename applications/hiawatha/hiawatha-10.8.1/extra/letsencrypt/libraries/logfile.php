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

	class logfile {
		private $type = null;
		private $entries = array();
		private $timestamp = null;

		/* Constructor
		 */
		public function __construct($type) {
			$this->type = $type;
			$this->timestamp = time();
		}

		/* Destructor
		 */
		public function __destruct() {
			$this->flush();
		}

		/* Write output buffer to disk
		 */
		public function flush() {
			if (count($this->entries) == 0) {
				return;
			}

			if (($fp = fopen($this->type.".log", "a")) == false) {
				return;
			}

			fprintf($fp, "----[ %s ]--------------------\n", date("r", $this->timestamp));

			foreach ($this->entries as $entry) {
				$entry = sprintf("%s\n", $entry);
				fputs($fp, $entry);
			}

			fclose($fp);

			$this->clean();
		}

		/* Clear the output buffer
		 */
		public function clean() {
			$this->entries = array();
		}

		/* Add item to output buffer
		 */
		public function add_entry($entry) {
			if (func_num_args() > 1) {
				$args = func_get_args();
				array_shift($args);
				$entry = vsprintf($entry, $args);
			}

			array_push($this->entries, $entry);
		}

		/* Add variable to output buffer
		 */
		public function add_variable($variable, $prefix = null) {
			ob_start();
			var_dump($variable);
			$variable = rtrim(ob_get_contents());
			ob_end_clean();

			$variable = preg_replace('/=>$\s*/m', " => ", $variable);

			if ($prefix !== null) {
				$variable = sprintf("%s: %s", $prefix, $variable);
			}

			$this->add_entry($variable);
		}
	}
?>
