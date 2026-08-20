from setuptools import find_packages
from setuptools import setup

with open('README.md', 'r') as readme_file:
    readme = readme_file.read()

with open('requirements.txt', 'r') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='pynipper-ng',
    version='0.2.0',
    author='Syn-4ck',
    author_email='repoJFM@protonmail.com',
    description='Configuration security analyzer for network devices',
    long_description=readme,
    long_description_content_type='text/markdown',
    url='https://github.com/syn-4ck/pynipper-ng',
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'src.report.templates': ['*.html', '*.js', '*.css'],
        'src.common': ['*.conf']
    },
    keywords=[
        'analyzer',
        'network-analysis',
        'network-security',
        'configuration-analysis',
        'python-tool'
    ],
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'pynipper-ng = src.main:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3.8',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Environment :: Console',
        'Operating System :: OS Independent',
    ],
)
