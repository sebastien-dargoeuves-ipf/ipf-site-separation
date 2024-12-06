from setuptools import setup, find_packages

setup(
    name='ipf-site-separation',
    version='1.0',
    packages=find_packages(include=['modules', 'modules.*']),  # Include the modules directory
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        'ipfabric',
        'loguru',
        'openpyxl',
        'pandas',
        'typer',
    ],
    extras_require={
        'snow': [
            'ipfabric_snow',
        ],
    },
)