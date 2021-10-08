import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="tplinkshutdown-tostis",
    version="0.9.3",
    author="Tostis",
    author_email="contact me on github",
    description="Simple python script to reboot a TP-Link Powerline Adapter",
    py_modules=['tplinkshutdown'],
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU GPLv3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={"console_scripts": ["tplinkshutdown=tplinkshutdown.main:main"]},
)


