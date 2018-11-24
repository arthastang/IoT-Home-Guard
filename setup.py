#!/usr/bin/python3
'''
Setup
'''
from setuptools import setup, find_packages

setup(
    name="IoT-Home-Guard",
    version="1.0",
    urls="https://github.com/arthastang/IoT-Home-Guard",
    author="Demesne",
    author_email="demesne0.0@gmail.com",
    description="A tool for malicious behavior detection in IoT devices.",
    packages=find_packages(),
    scripts=["IoT-Home-Guard.py"],
    url=['https://github.com/yaml','https://github.com/lxml/lxml'],
    install_requires=["cmd2>=0.9.4","pyyaml", "pyserial>=3.4","pyshark"],
    python_requires=">=3.6"
        
)
