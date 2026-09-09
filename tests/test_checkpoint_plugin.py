import pytest
import os
from src.devices import get_parser
from src.analyze.checkpoint.plugins.fw1_checks_plugin import PluginCheckPointChecks
from src.devices.checkpoint.fw1 import CheckPointFW1Parser

def test_plugin_checkpoint_checks():
    # We need a dummy directory as CheckPoint parser expects a directory
    test_dir = "tests/test_data/checkpoint_test_dir"
    os.makedirs(test_dir, exist_ok=True)
    
    # CheckPoint parser expects specific filenames
    config_path = os.path.join(test_dir, "objects.C")
    # This dummy file content needs to be palatable to the rudimentary parser
    with open(config_path, "w") as f:
        f.write("( :objects ( :obj1 ( any ) ) )")
        
    rules_path = os.path.join(test_dir, "rules.C")
    with open(rules_path, "w") as f:
        f.write("( :rules ( :rule1 ( :action ( accept ) :object ( any ) ) ) )")
        
    parser = get_parser("CHECKPOINT", test_dir)
    assert isinstance(parser, CheckPointFW1Parser)
    
    plugin = PluginCheckPointChecks()
    plugin.analyze(parser)
    
    issues = plugin.get_issues()
    assert len(issues) == 2
    assert any("Insecure Object Definition" in issue.title for issue in issues)
    assert any("Broad Filter Rule Detected" in issue.title for issue in issues)
    
    # Cleanup
    os.remove(config_path)
    os.remove(rules_path)
    # The parser seems to be leaving something behind or I have a typo, let's fix it by using shutil
    import shutil
    shutil.rmtree(test_dir, ignore_errors=True)
