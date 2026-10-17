from setuptools import setup, find_packages

setup(
    name="ebpf-runtime-sandbox-analyzer",
    version="1.0.0",
    description="Simulated kernel-level system call behavioral analytics engine to trap malicious supply-chain package executions",
    author="Architecture Labs",
    packages=find_packages(),
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
    ],
)
