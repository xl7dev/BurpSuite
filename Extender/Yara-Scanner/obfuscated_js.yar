rule obfuscated_js
{
   meta:
      description = "Obfuscated Javascript Detection"
      author = "ian@politoinc.com"
      date = "26 Jan 2016"
      version = "1"
      impact = 3
      hide = false
   strings:
      $a = "eval"
	  $b = "%"
	  $c = "\\x"
	  $d = ".fromCharCode"
   condition:
      $a and (#b > 20 or #c > 20 or $d)
}
