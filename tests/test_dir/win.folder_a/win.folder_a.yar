rule win_folder_a
{
    strings:
        $rule1 = "rule1_matches_me"
    condition:
        $rule1
}
