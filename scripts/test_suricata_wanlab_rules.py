import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SuricataWanlabRulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        decoder = ET.parse(
            ROOT / "config" / "wazuh" / "decoders"
            / "pfsense_suricata_wanlab_decoder.xml"
        ).getroot()
        cls.prematch = re.compile(decoder.findtext("prematch"))
        cls.pattern = re.compile(decoder.findtext("regex"))
        cls.order = decoder.findtext("order").split(",")
        rules = ET.parse(
            ROOT / "config" / "wazuh" / "rules" / "linux"
            / "010-linux-pfsense_suricata_wanlab_rules.xml"
        ).getroot()
        cls.base = rules.find("rule[@id='110200']")
        cls.children = [
            rule for rule in rules.findall("rule")
            if rule.findtext("if_sid") == "110200"
        ]

    def test_sid_classification_and_endpoints(self):
        cases = [
            (1000201, "ICMP", None, "110201"),
            (1000206, "ICMP", None, "110201"),
            (1000202, "TCP", 22, "110202"),
            (2003068, "TCP", 22, "110202"),
            (1000203, "TCP", 3389, "110203"),
            (1000204, "TCP", 445, "110204"),
            (1000205, "TCP", 443, "110205"),
            (9999999, "TCP", 22, "110200"),
        ]
        self.assertEqual(self.base.findtext("decoded_as"), "pfsense-suricata-wanlab")
        self.assertEqual(self.pattern.groups, len(self.order))
        for sid, protocol, port, expected in cases:
            for classification in ("", "[Classification: Attempted Information Leak] "):
                with self.subTest(sid=sid, classification=classification):
                    source = "10.10.10.101" + (":51515" if port else "")
                    target = "192.168.99.19" + (f":{port}" if port else "")
                    message = "ET SCAN Potential SSH Scan OUTBOUND" if sid == 2003068 else "WAN LAB - TEST"
                    log = (
                        f"Nov  3 11:32:57 suricata[57578]: [1:{sid}:1] "
                        f"{message} {classification}[Priority: 2] "
                        f"{{{protocol}}} {source} -> {target}"
                    )
                    self.assertIsNotNone(self.prematch.search(log))
                    match = self.pattern.search(log)
                    self.assertIsNotNone(match)
                    fields = dict(zip(self.order, match.groups()))
                    self.assertEqual(fields["suricata_sid"], str(sid))
                    self.assertEqual(fields["srcip"], "10.10.10.101")
                    self.assertEqual(fields["dstip"], "192.168.99.19")
                    self.assertEqual(fields["dstport"], str(port) if port else None)
                    matching = [
                        rule.attrib["id"] for rule in self.children
                        if re.fullmatch(rule.findtext("field"), fields["suricata_sid"])
                    ]
                    self.assertEqual(matching, [] if expected == "110200" else [expected])

    def test_unrelated_syslog_is_not_decoded(self):
        self.assertIsNone(self.prematch.search(
            "Nov 3 11:16:42 filterlog[33475]: block,in,udp,77"
        ))


if __name__ == "__main__":
    unittest.main()
