#!/usr/bin/env python3

import unittest
from replayer_mismatch.handler import *

"""Tests for the UCFS claimant API replayer mismatch handler lambda."""


class TestReplayer(unittest.TestCase):
    def test_replay_original_request(self):
        tests_written = False

        self.assertFalse(tests_written)
