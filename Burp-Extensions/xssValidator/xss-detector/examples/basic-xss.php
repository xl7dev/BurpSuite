<?php
/**
 * This is the most basic example of XSS.
 *
 * In this example, the application directly echos
 * a string that is passed into the GET parameter, test.
 *
 * This example also serves to demonstrate that xssDetector
 * only reports XSS if the function triggered contains the
 * trigger phrase. For example, the alert("notxss") function
 * does not trigger the xss findings.
 */
?>
<html>
<body>
<?php
echo 'hello';
echo $_GET['test'];
?>
<script>alert("notxs");</script></body>
</html>
