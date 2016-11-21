rule req_test
{
    meta:
        description = "a very simple example rule that should generate request matches for testing purposes; feel free to modify"
    strings:
        $a = "GET"
        $b = "POST"
    condition:
        $a or $b
}
