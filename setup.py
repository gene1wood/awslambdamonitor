# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='awslambdamonitor',
    version='1.0.0',
    description='A small monitoring tool which runs in AWS Lambda',
    long_description=long_description,
    url='https://github.com/gene1wood/awslambdamonitor',
    author='Gene Wood',
    author_email='gene_wood@cementhorizon.com',
    license='GPL-3.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Monitoring',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='aws lambda monitoring ses',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    # Alternatively, if you want to distribute just a my_module.py, uncomment
    # this:
    #   py_modules=["my_module"],

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['ndg-httpsclient',
                      'paramiko',
                      'ecdsa',
                      'pycrypto',
                      'python-whois',
                      'PyYAML',
                      'boto3',
                      'requests',
                      'pyOpenSSL',
                      'pyasn1'],
)
