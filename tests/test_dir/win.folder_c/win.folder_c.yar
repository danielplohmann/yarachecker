rule win_folder_b_broken
{
    strings:
        $rule_invalid = "condition without valid string"
    condition:
        $invalid
}
