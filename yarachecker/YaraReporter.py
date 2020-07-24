import json
import os
import re
import sys
from tqdm import tqdm
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)

from yarachecker.YaraScanner import YaraScanner


class StatTracker:

    def __init__(self):
        self.num_samples_covered = 0
        self.num_samples_all = 0
        self.num_families_covered = 0
        self.num_rules = 0
        self.num_true_positives = 0
        self.num_false_positives = 0
        self.num_true_negatives = 0
        self.num_false_negatives = 0
        self.false_positives = defaultdict(dict)
        self.false_negatives = defaultdict(set)
        self.rule_errors = []

    def update(self, family, sample, is_covered, matches):
        print("updating stats: ", family, sample, is_covered, matches)
        escaped_family = family.replace(".", "_")
        has_true_match = False
        self.num_samples_all += 1
        if is_covered:
            self.num_samples_covered += 1
        if matches:
            for rule in matches:
                print("evaluating rule: ", rule)
                if rule.startswith(escaped_family):
                    has_true_match = True
                else:
                    if rule in self.false_positives[family]:
                        self.false_positives[family][rule].append(sample)
                    else:
                        self.false_positives[family][rule] = [sample]
                    print("updating FPs", self.false_positives)
            if has_true_match:
                self.num_true_positives += 1
            print("updating count", self.false_positives, len(self.false_positives))
            self.num_false_positives += len(self.false_positives)
        else:
            if is_covered:
                self.num_false_negatives += 1
                self.false_negatives[family].add(sample)
            else:
                self.num_true_negatives += 1

    def getStats(self):
        stats = {
            # number of rules
            "num_rules": self.num_rules,
            # a rule detects a sample of its family
            "num_true_positives": self.num_true_positives,
            # a rule detects a sample of another family
            "num_false_positives": self.num_false_positives,
            # a rule does not detect a sample of its family
            "num_false_negatives": self.num_false_negatives,
            # samples not covered by rules
            "num_true_negatives": self.num_true_negatives,
            # samples we cover with rules
            "num_samples_covered": self.num_samples_covered,
            # all samples
            "num_samples_all": self.num_samples_all,
            # number of families with rules
            "num_families_covered": self.num_families_covered,
            # F-Score for families with rules
            "F_Score_covered": 0,
            # F-Score, but treating TNs also as FNs
            "F_Score_all": 0,
            "false_positives": {key: dict(value) for (key, value) in dict(self.false_positives).items()},
            "false_negatives": {key: list(value) for (key, value) in dict(self.false_negatives).items()},
            "rule_errors": list(set(self.rule_errors))
        }
        if self.num_true_positives or self.num_false_positives:
            covered_precision = 1.0 * self.num_true_positives / (self.num_true_positives + self.num_false_positives)
            covered_recall = 1.0 * self.num_true_positives / self.num_samples_covered
            all_precision = 1.0 * self.num_true_positives / (self.num_true_positives + self.num_false_positives)
            all_recall = 1.0 * self.num_true_positives / self.num_samples_all
            stats["F_Score_covered"] = 2.0 * (covered_precision * covered_recall) / (covered_precision + covered_recall)
            stats["F_Score_all"] = 2.0 * (all_precision * all_recall) / (all_precision + all_recall)
        return stats

class YaraReporter:

    def __init__(self, directory=None, show_progress=False):
        self.is_showing_progress = show_progress
        self.yara_scanner = YaraScanner()
        self.stat_tracker = StatTracker()
        self.files_to_scan = self.collectScanFiles(directory) if directory else {}
        self.rules = self.collectRules(directory) if directory else {}

    def report(self):
        scan_results = self._scan()
        scan_results["stats"] = self._generateStats(scan_results)
        return scan_results

    def _generateStats(self, results):
        self.stat_tracker.rule_errors = self.yara_scanner.getRuleErrors()
        self.stat_tracker.num_families_covered = len(self.rules)
        self.stat_tracker.num_rules = sum([len(self.rules[family]) for family in self.rules])
        for family in results["matches"]:
            is_covered = family in self.rules
            for sample in results["matches"][family]:
                sample_name = os.path.basename(sample)
                if re.search(r"[0-9a-f]{64}_dump7?_0x[0-9a-f]{8,16}", sample_name) or re.search(r"[0-9a-f]{64}_unpacked$", sample_name):
                    sample_matches = results["matches"][family][sample]
                    self.stat_tracker.update(family, sample_name, is_covered, sample_matches)
        return self.stat_tracker.getStats()

    def _scan(self):
        results = {}
        results["matches"] = defaultdict(dict)

        steps = sum([len(self.files_to_scan[family]) for family in self.files_to_scan])
        with tqdm(total=steps, smoothing=0.1) as pbar:
            for family in self.files_to_scan:
                for filepath in self.files_to_scan[family]:
                    hits = self.yara_scanner.scanFile(filepath)
                    results["matches"][family][filepath] = [hit.rule_name for hit in hits if hit.hasMatch()]
                    pbar.update(1)
        results["matches"] = dict(results["matches"])
        return results


    def collectRules(self, base_dir):
        target_files = defaultdict(list)

        abs_base_dir = str(os.path.abspath(base_dir))
        for toplevel_dir in os.listdir(abs_base_dir):
            if not os.path.isdir(abs_base_dir + os.sep + toplevel_dir) or ".git" in toplevel_dir:
                continue
            loaded_rules = self.yara_scanner.addRules(abs_base_dir + os.sep + toplevel_dir)
            if loaded_rules:
                target_files[toplevel_dir] = loaded_rules
        LOG.info("Collected rules: %d", len(self.yara_scanner.getRules()))
        return dict(target_files)

    def collectScanFiles(self, base_dir):
        target_files = defaultdict(list)

        abs_base_dir = str(os.path.abspath(base_dir))
        num_family_levels = len(abs_base_dir.split(os.sep))
        num_scan_files = 0
        for root, subFolders, files in os.walk(abs_base_dir):
            if root == abs_base_dir or ".git" in root:
                continue
            for filename in sorted(files):
                family = root.split("/")[num_family_levels]
                if re.search(r"[0-9a-f]{64}", filename):
                    target_files[family].append(root + os.sep + filename)
                    num_scan_files += 1
        LOG.info("Collected files to scan: %d", num_scan_files)
        return dict(target_files)
