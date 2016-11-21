rule resp_test
{
    meta:
        description = "simple example rule that should generate matches for responses for testing purposes; feel free to modify"
    strings:
        $a = "Set-Cookie" nocase
        $b = "html" nocase
        $c = "<script>" nocase
        $d = /\d+\.\d+\.\d+\.\d+/
    condition:
        $a or $b or $c or $d
}
