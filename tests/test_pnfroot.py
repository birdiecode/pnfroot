import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pnfroot", ROOT / "pnfroot.py")
pnfroot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pnfroot)


class PnfrootTests(unittest.TestCase):
    def test_pull_image_from_existing_rootfs_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "image"
            pulled_path = pnfroot.pull_image_to_dir("ubuntu_c", output=str(output_dir))

            self.assertTrue(Path(pulled_path).exists())
            self.assertTrue((Path(pulled_path) / "etc").exists())


if __name__ == "__main__":
    unittest.main()
