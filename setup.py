from setuptools import setup, find_packages

required = [
    "treeherder-client==2.1.0",
]

setup(
    name='treeherder-submitter',
    version='0.2.2',
    packages=find_packages(),
    install_requires=required,
    tests_require=required,
    # Meta-data for upload to PyPI
    author='Armen Zambrano G.',
    author_email='armenzg@mozilla.com',
    description='It is a helper library to submit jobs to Treeherder',
    license='MPL',
    url='https://github.com/armenzg/treeherder_submitter',
)
