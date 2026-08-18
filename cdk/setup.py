import setuptools


with open("../README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="jupyter_ecs_service",
    version="0.0.1",

    description="AWS CDK stack for Jupyter ECS service",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="Avishay Bar",

    package_dir={"": "jupyter_ecs_service"},
    packages=setuptools.find_packages(where="jupyter_ecs_service"),

    install_requires=[
        "aws-cdk-lib>=2.100.0,<3.0.0",
        "constructs>=10.0.0,<11.0.0",
        "PyYAML>=6.0",
    ],

    python_requires=">=3.9",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
