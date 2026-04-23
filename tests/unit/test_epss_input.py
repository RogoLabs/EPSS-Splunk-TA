import os
import subprocess
import sys
import xml.etree.ElementTree as ET

EPSS_PY = os.path.join(os.path.dirname(__file__), "..", "..", "TA-epss", "bin", "epss.py")


def test_scheme_returns_valid_xml():
    """subprocess runs epss.py --scheme, parses XML, exit code 0."""
    result = subprocess.run(
        [sys.executable, EPSS_PY, "--scheme"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    root = ET.fromstring(result.stdout)
    assert root.tag == "scheme"


def test_scheme_title_matches_input_stanza():
    """<title> text must be exactly 'epss' to match inputs.conf stanza."""
    result = subprocess.run(
        [sys.executable, EPSS_PY, "--scheme"],
        capture_output=True,
        text=True,
    )
    root = ET.fromstring(result.stdout)
    title = root.find("title")
    assert title is not None
    assert title.text == "epss"


def test_scheme_has_required_args():
    """Scheme must have lookback_days, batch_size, epss_base_url args."""
    result = subprocess.run(
        [sys.executable, EPSS_PY, "--scheme"],
        capture_output=True,
        text=True,
    )
    root = ET.fromstring(result.stdout)
    args = root.findall(".//arg")
    arg_names = {arg.get("name") for arg in args}
    assert "lookback_days" in arg_names
    assert "batch_size" in arg_names
    assert "epss_base_url" in arg_names
