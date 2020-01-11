import setuptools

with open('README.md', 'r') as fh:
	long_description = fh.read()

setuptools.setup(
	name='CKAN-Downloader-EncryptedKitten',
	version='0.0.3',
	author='EncryptedKitten',
	author_email='carterdwatson@gmail.com',
	description='A tool to download all of The Comprehensive Kerbal Archive Network (https://github.com/KSP-CKAN/CKAN).',
	long_description=long_description,
	long_description_content_type='text/markdown',
	url='https://github.com/EncryptedKitten/CKAN-Downloader',
	packages=setuptools.find_packages(),
	classifiers=[
		'Programming Language :: Python :: 3.8',
		'License :: OSI Approved :: MIT License',
		'Operating System :: OS Independent',
	],
	python_requires='>=3.8',
	install_requires=[
          'requests',
		  'pathvalidate'
      ],
)