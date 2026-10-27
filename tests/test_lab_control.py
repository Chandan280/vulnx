import unittest
from unittest.mock import patch
from backend import lab_control


class LabControlTests(unittest.TestCase):
    def test_missing_docker_is_unavailable_not_running(self):
        with patch.object(lab_control.shutil,'which',return_value=None):
            self.assertFalse(lab_control.status()['available'])
            with self.assertRaises(RuntimeError):lab_control.lifecycle('start')

    def test_only_fixed_actions_are_allowed(self):
        with self.assertRaises(ValueError):lab_control.lifecycle('start; rm -rf /')

    def test_reset_only_touches_named_compose_project(self):
        with patch.object(lab_control,'status',return_value={'available':True,'running':True}),patch.object(lab_control,'run') as run:
            lab_control.lifecycle('reset')
            calls=[c.args[0] for c in run.call_args_list]
            self.assertEqual(calls[0][-2:],['down','--volumes'])
            self.assertIn('vulnx-lab',calls[0])
            self.assertEqual(calls[1][-6:],['up','-d','--build','--wait','--wait-timeout','60'])

    def test_corrected_mode_uses_only_fixed_exec_script(self):
        with patch.object(lab_control,'status',return_value={'running':True}),patch.object(lab_control,'run') as run:
            self.assertEqual(lab_control.set_mode(True),'docker')
            args=run.call_args.args[0]
            self.assertEqual(args[:4],['exec','vulnx-training-lab','python','-c'])
            self.assertIn('p.touch()',args[-1])
