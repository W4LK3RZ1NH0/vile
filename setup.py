from setuptools import setup, find_packages

setup(
    name="vile",
    version="1.1.0",
    author="W4LK3R",
    description="Vulnerability & Intelligence Lookup Engine",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/W4LK3RZ1NH0/vile",
    
    # Apenas esta linha de packages deve existir:
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    
    include_package_data=True,
    install_requires=[
        "requests>=2.25.0",
    ],
    entry_points={
        "console_scripts": [
            "vile=vile.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)