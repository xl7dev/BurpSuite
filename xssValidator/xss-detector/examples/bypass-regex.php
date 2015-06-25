<?php
/**
 * This application demonstrates the ability to bypass
 * single-pass regex' that attempt to search and replace
 * malicious input
 */
?>
<html>
<body>
	Hello: <?= filter_output($_GET['name']); ?>
</body>
</html>

<?php
function filter_output($val) {
	$val = strtolower($val);
	$val = preg_replace("/<script>/", "", $val);
	$val = preg_replace("/<\/script>/", "", $val);
	return $val;
}
?>