import json
import sys
from yarachecker import YaraReporter


if len(sys.argv) > 1:
    reporter = YaraReporter(sys.argv[1])
    report = reporter.report()
    print("Stats:")
    print(json.dumps(report["stats"], indent=1, sort_keys=True))
else:
    print("usage: {} <path with yara rules> <binary to scan>".format(sys.argv[0]))
