# CKAN-Downloader
A tool to download all of The [Comprehensive Kerbal Archive Network](https://github.com/KSP-CKAN/CKAN).
It is avalible on PyPI at [https://pypi.org/project/CKAN-Downloader-EncryptedKitten/](https://pypi.org/project/CKAN-Downloader-EncryptedKitten/) and can be installed with `pip install CKAN-Downloader-EncryptedKitten`.
## Usage
Run it with the `-h` flag to see the options.
It will output all of the files to the save path, and in the local CKAN repos will be in the repositories subdirectory.
The script defaults to outputting the files to 'CKAN Archive' in the current directory and using http://localhost as the host for the CKAN repo.

This script requires a web server, for example if you set the current directory to your save path and want to run the server with the [PHP built-in server](https://www.php.net/manual/en/features.commandline.webserver.php), `php -S localhost:80` would run the server at http://localhost:80.

To add it to CKAN under the default settings, you can add the main repo, add `your_repo_name | http://localhost/repositories/default.tar.gz`.
To disable CKAN caching downloads, set 'Maximum cache size' to 0.
