import sys, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vpsmanager.proxy import select_cascade_inbounds
class CascadeSelectionTests(unittest.TestCase):
    def test_empty_does_not_prompt(self):
        with patch('builtins.input') as prompt:
            self.assertEqual(select_cascade_inbounds([]),[])
            prompt.assert_not_called()
    def test_select_uses_actual_tag_not_display_number(self):
        entries=[{'id':77,'tag':'custom-tag','port':443,'remark':'fixture'}]
        with patch('builtins.input',return_value='1'):
            self.assertEqual(select_cascade_inbounds(entries),['custom-tag'])
    def test_invalid_selection_can_be_cancelled(self):
        with patch('builtins.input',side_effect=['99','0']):
            self.assertEqual(select_cascade_inbounds([{'tag':'one'}]),[])
    def test_missing_tags_are_not_guessed(self):
        with patch('builtins.input') as prompt:
            self.assertEqual(select_cascade_inbounds([{'id':1,'port':443}]),[])
            prompt.assert_not_called()
