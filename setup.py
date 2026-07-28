from setuptools import find_packages, setup

setup(
    name="chronos-pse",
    version="2.0.0",
    description="Chronos: Password Risk & Crack-Time Intelligence Engine — composite "
                 "risk scoring, crack-time estimation, breach/hash/wordlist/policy "
                 "auditing, and organization-wide HTML risk reporting.",
    author="SM Moniruzzaman",
    packages=find_packages(exclude=["tests*"]),
    package_data={"chronos": []},
    include_package_data=True,
    install_requires=[
        "requests>=2.31.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "chronos=chronos.cli:main",
        ],
    },
    python_requires=">=3.10",
)
