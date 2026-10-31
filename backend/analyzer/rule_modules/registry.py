from . import cwe_78, cwe_79, cwe_89, cwe_352, cwe_787, cwe_862, cwe_918

RULES = {
    rule.cwe_id: rule
    for rule in (
        cwe_78.RULE,
        cwe_79.RULE,
        cwe_89.RULE,
        cwe_352.RULE,
        cwe_787.RULE,
        cwe_862.RULE,
        cwe_918.RULE,
    )
}
