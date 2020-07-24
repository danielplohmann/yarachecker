rule win_folder_b
{
    strings:
        $rule2 = "rule2_matches_me"
    condition:
        $rule2
}

rule win_folder_b_fp
{
    strings:
        $rule_fp = "matches_me"
    condition:
        $rule_fp
}
