#!/usr/bin/python
########################################################################
# Copyright (c) 2014
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  This file is part of IDAscope
#
#  IDAscope is free software: you can redistribute it and/or modify it
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
# Credits:
# * Christopher Kannen for contributing an independent loader for
#   YARA rules which allows to display unmatched rules and
#   content of rule files as loaded by yara-python
########################################################################

import os
import re
import time
import traceback
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    print("[-] ERROR: Could not import YARA (not installed?), scanner disabled.")
    yara = None

from yarachecker.YaraRule import YaraRule
from yarachecker.YaraRuleLoader import YaraRuleLoader


class YaraScanner(object):
    """
    A module to analyze and explore an IDB for semantics. For a set of API names, references to these
    are identified and used for creating context and allowing tagging of them.
    """

    def __init__(self):
        # fields
        self.yrl = YaraRuleLoader()
        self.num_files_loaded = 0
        self._compiled_rules = []
        self._rule_errors = []
        self._yara_rules = []
        self._results = []
        self.base_addr = 0

    def getRules(self):
        return self._yara_rules

    def getRuleErrors(self):
        return self._rule_errors

    def getResults(self):
        return self._results

    def loadRules(self, yara_path):
        self.num_files_loaded = 0
        self._compiled_rules = []
        self._yara_rules = []
        return self._load_recursive(yara_path)

    def addRules(self, yara_path):
        return self._load_recursive(yara_path)

    def _load_recursive(self, yara_path):
        loaded_rules = []
        if os.path.isfile(yara_path):
            loaded_rules = self._load_file(yara_path)
        elif os.path.isdir(yara_path):
            for dirpath, _, filenames in os.walk(yara_path):
                for filename in sorted(filenames):
                    if filename.endswith(".yar") or filename.endswith(".yara"):
                        filepath = dirpath + os.sep + filename
                        loaded_rules.extend(self._load_file(filepath))
        return loaded_rules

    def _load_file(self, filepath):
        rules_from_file = []
        try:
            rules = yara.compile(filepath)
            rules_from_file = self.yrl.loadRulesFromFile(filepath)
            self._yara_rules.extend(rules_from_file)
            self._compiled_rules.append(rules)
            LOG.debug("loading rules from file: %s (%d)", filepath, len(rules_from_file))
            if rules:
                self.num_files_loaded += 1
        except Exception as exc:
            LOG.warn("Could not load yara rules from file: %s", filepath)
            self._rule_errors.append(os.path.basename(filepath)[:-4])
        return rules_from_file

    def scanFile(self, filepath):
        base_addr = 0
        base_addr_match = re.search(r"0x[a-fA-F0-9]{8}", filepath)
        if base_addr_match:
            base_addr = int(base_addr_match.group(), 16)
        binary = ""
        with open(filepath, "rb") as f_bin:
            binary = f_bin.read()
        return self.scan(binary, base_addr)

    def scan(self, memory, base_addr):
        self._results = []
        self.base_addr = base_addr
        matches = []
        LOG.debug("Performing YARA scan on buffer: %d bytes @0x%x", len(memory), base_addr)
        for rule in self._compiled_rules:
            matches.append(rule.match(data=memory, callback=self._result_callback))
        return self._results

    def _result_callback(self, data):
        adjusted_offsets = []
        for string in data["strings"]:
            adjusted_offsets.append((self.base_addr + string[0], string[1], string[2]))
        data["strings"] = adjusted_offsets
        if data["matches"]:
            LOG.debug("YARA Match for signature: %s", data["rule"])
        result_rule = None
        for rule in self._yara_rules:
            if rule.rule_name == data["rule"]:
                result_rule = rule
        result_rule.match_data = data
        self._results.append(result_rule)
        yara.CALLBACK_CONTINUE
