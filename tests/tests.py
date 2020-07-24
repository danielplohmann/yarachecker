# -*- coding: utf-8 -*-
########################################################################
# Copyright (c) 2017
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of YaraHealthCheck
#
#  apiscout is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

import logging
import struct
import os
import unittest

from .context import yarachecker
from yarachecker.YaraReporter import YaraReporter

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")


class YaraCheckerTestSuite(unittest.TestCase):
    """Basic test cases."""

    maxDiff = None
    test_dir = os.path.abspath("tests/test_dir")

    def removeAbsBase(self, src):
        # TODO: reformulate as recursive function over dicts, lists, strings
        result = None
        if isinstance(src, dict):
            result = {}
            for k, v in src.items():
                result[self.removeAbsBase(k)] = self.removeAbsBase(v)
        elif isinstance(src, list):
            result = []
            for i in src:
                result.append(self.removeAbsBase(i))
        elif isinstance(src, str):
            result = src
            if src.startswith(self.test_dir):
                result = src[len(self.test_dir):]
        return result

    def testGenerateStats(self):
        reporter = YaraReporter(self.test_dir)
        stats = reporter._generateStats(reporter._scan())
        expected = {
            "F_Score_all": 0.5714285714285715,
            "F_Score_covered": 0.6666666666666666,
            "false_positives": {
                "win.folder_a": {
                    "win_folder_b_fp": [
                        "273407be9bdb57e679bd5d58e52f91742a3b4086722104b626c860da0ebee9df_dump_0x00000000"
                    ]
                }
            },
            'false_negatives': {
                'win.folder_b': [
                    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855_unpacked'
                ]
            },
            "num_false_negatives": 1,
            "num_false_positives": 1,
            'num_families_covered': 2,
            'num_rules': 3,
            'rule_errors': [
                "win.folder_c"
            ],
            "num_true_negatives": 1,
            "num_true_positives": 2,
            'num_samples_all': 4,
            'num_samples_covered': 3
        }
        self.assertEqual(expected, stats)

    def testScan(self):
        reporter = YaraReporter(self.test_dir)
        collected = reporter._scan()
        collected_matches = collected["matches"]
        expected = {
            "win.folder_a": {
                "/win.folder_a/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": [],
                "/win.folder_a/273407be9bdb57e679bd5d58e52f91742a3b4086722104b626c860da0ebee9df_dump_0x00000000": ["win_folder_b_fp", "win_folder_a"]
            },
            "win.folder_c": {
                "/win.folder_c/75181d4b5ab2d6d21d5b862d17224a2d4b9acc7483fa8333c7fca2d727f25978_dump_0x00000000": []
            },
            "win.folder_b": {
                "/win.folder_b/subfolder2_1/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855_unpacked": [],
                "/win.folder_b/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": [],
                "/win.folder_b/44cec1a726cbf333a6b69345ab1f6eb1c1159a821f3289ee1142d879564a5f8a": ["win_folder_b", "win_folder_b_fp"],
                "/win.folder_b/44cec1a726cbf333a6b69345ab1f6eb1c1159a821f3289ee1142d879564a5f8a_unpacked": ["win_folder_b", "win_folder_b_fp"]
            }
        }
        self.assertEqual(expected, self.removeAbsBase(collected_matches))

    def testLoadAllRules(self):
        reporter = YaraReporter()
        collected = reporter.collectRules(self.test_dir)
        print(collected)
        self.assertEqual(sorted(collected.keys()), ["win.folder_a", "win.folder_b"])
        self.assertEqual(1, len(collected["win.folder_a"]))
        self.assertEqual(2, len(collected["win.folder_b"]))


    def testCollectFiles(self):
        reporter = YaraReporter()
        expected = {
            'win.folder_a': [
                '/win.folder_a/273407be9bdb57e679bd5d58e52f91742a3b4086722104b626c860da0ebee9df_dump_0x00000000',
                '/win.folder_a/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
            'win.folder_b': [
                '/win.folder_b/44cec1a726cbf333a6b69345ab1f6eb1c1159a821f3289ee1142d879564a5f8a',
                '/win.folder_b/44cec1a726cbf333a6b69345ab1f6eb1c1159a821f3289ee1142d879564a5f8a_unpacked',
                '/win.folder_b/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                '/win.folder_b/subfolder2_1/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855_unpacked'],
            'win.folder_c': [
                '/win.folder_c/75181d4b5ab2d6d21d5b862d17224a2d4b9acc7483fa8333c7fca2d727f25978_dump_0x00000000'
            ]
            }
        self.assertEqual(expected, self.removeAbsBase(reporter.collectScanFiles(self.test_dir)))

    def testFullCoverage(self):
        reporter = YaraReporter(self.test_dir)
        reporter.report()


if __name__ == '__main__':
    unittest.main()
