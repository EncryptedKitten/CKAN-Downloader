#EncryptedKitten's CKAN Downloader. This script is a Python 3.8 script. Comments and log entries that end with a URL, filename, or variable name will have a tab (\t) to separate the period from the last word. You will need to install requests and pathvalidate. This script will download all of the mod files a specified CKAN repository.

import time, os, requests, logging, json, hashlib, cgi, tarfile, io, pathvalidate, argparse

#Set what hash algorithms to use to check file download integrity.
CHECK_SIZE = True
CHECK_SHA_1_HASH = True
CHECK_SHA_256_HASH = True

#Set other options.
DRY_RUN = False
SAVE_PATH = 'CKAN Archive'
DOWNLOAD_ATTEMPTS = 3
LOG_FILE_NAME = 'CKAN Downloader.log'
VERIFY_WRITES = True
LOCAL_DOWNLOAD_ROOT = 'http://localhost'
CKAN_MAIN_REPO_URL = 'https://github.com/KSP-CKAN/CKAN-meta/archive/master.tar.gz'
NO_DOWNLOAD = False


def logging_setup():
	global LOG_FILE_NAME

	LOG_FILE_NAME = pathvalidate.sanitize_filepath(LOG_FILE_NAME, replacement_text='_')

	logFormatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s][%(message)s]')
	rootLogger = logging.getLogger()

	if os.path.dirname(LOG_FILE_NAME):
		os.makedirs(os.path.dirname(LOG_FILE_NAME), exist_ok=True)

	fileHandler = logging.FileHandler(LOG_FILE_NAME)
	fileHandler.setFormatter(logFormatter)
	fileHandler.setLevel(logging.DEBUG)
	rootLogger.addHandler(fileHandler)

	consoleHandler = logging.StreamHandler()
	consoleHandler.setFormatter(logFormatter)
	consoleHandler.setLevel(logging.INFO)
	rootLogger.addHandler(consoleHandler)

	rootLogger.setLevel(logging.DEBUG)

def check_success(successful, mod_file, content):
	if 'download_size' in mod_file:
		successful = successful and check_size(content, mod_file['download_size'])

	if 'download_hash' in mod_file:
		if 'sha1' in mod_file['download_hash']:
			successful = successful and check_sha_1_hash(content, mod_file['download_hash']['sha1'])
		if 'sha256' in mod_file['download_hash']:
			successful = successful and check_sha_256_hash(content, mod_file['download_hash']['sha256'])
	
	return successful

def check_for_zip(mod_save_path):
	if os.path.isdir(mod_save_path):
		for item in os.listdir(mod_save_path):
			item = mod_save_path + os.path.sep + item
			if os.path.isfile(item) and os.path.splitext(item)[-1] == '.zip':
				return item
	return None

def get_mod_save_path(mod_file, repository):
	return pathvalidate.sanitize_filepath(SAVE_PATH + os.path.sep + repository + os.path.sep + mod_file['identifier'] + os.path.sep + mod_file['version'], replacement_text='_')

def download_file(mod_file, repository):
	#Default this to false; if it has an exception, it definitely wasn't successful.
	successful = False
	
	try:
		#Set the mod's file to be saved in SAVE_PATH/repository/identifier/version	.
		mod_save_path = get_mod_save_path(mod_file, repository)

		#Check for existing .zip files, and use them if they are there.

		if zip_check := check_for_zip(mod_save_path):
			filename = zip_check
			successful = True
			logging.info('Found existing .zip file on filesystem at ' +  filename + '\t.')
		
		else:
			r = requests.get(mod_file['download'])

			content = r.content
			successful = check_status(r.status_code)

			successful = check_success(successful, mod_file, content)

			if successful:

				#Check if Content-Disposition header is present. This header provides a file name. For more information https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition	.
				if 'Content-Disposition' in r.headers:
					#cgi.parse_header(r.headers['Content-Disposition'])[1]['filename'] works by the following: r.headers['Content-Disposition'] is a string, for example 'attachment; filename=Kopernicus-1.7.3-2.zip'. cgi.parse_header(r.headers['Content-Disposition']) will return a tuple, for example ('attachment', {'filename': 'Kopernicus-1.7.3-2.zip'}) where at index 0 it has the value, in this example being 'attachment', while index 1, accessible cgi.parse_header(r.headers['Content-Disposition'])[1], has the parameters for example {'filename': 'Kopernicus-1.7.3-2.zip'}. The 'filename' parameter contains the intended filename, and it will be used for the name of the file if it is present.
					filename = os.path.join(mod_save_path, cgi.parse_header(r.headers['Content-Disposition'])[1]['filename'])
				else:
					#If there is no Content-Disposition header, just use the last part of the url (the part after the last '/') as the file name.
					filename = os.path.join(mod_save_path, r.url.split('/')[-1])
				
				#Remove invalid characters from the path.
				filename = pathvalidate.sanitize_filepath(filename, replacement_text='_')

				if DRY_RUN:
					#It is a dry run, so no data will be written to the filesystem
					logging.debug('DRY_RUN is enabled, but the file would have been written to the filesystem at ' +  filename + '\t.')

				else:
					#Make the directories for the file.
					os.makedirs(mod_save_path, exist_ok=True)

					#Opens the file for binary writes, writes the data, then closes the file.
					f = open(filename, 'wb')
					f.write(r.content)
					f.close()

					logging.debug('DRY_RUN is disabled, so the file was written to the filesystem at ' +  filename + '\t.')

		if not DRY_RUN and VERIFY_WRITES and successful:
			#Opens the file for a binary reads, reads the data, then closes the file.
			f = open(filename, 'rb')
			content = f.read()
			f.close()

			#VERIFY_WRITES is enabled, so it will use the data that was read from the file to check the data that is on the filesystem against the size and hashes. This will then be logged, and if it failed, the file will be removed.
			successful = check_success(True, mod_file, content)
			
			if successful:
				logging.debug('VERIFY_WRITES is enabled, and the verification was successful.')
			else:
				#Remove the failed file.
				os.remove(filename)
				
				#Remove the now empty directories too. It will be indexed in reverse because it must remove the deepest empty directory first. dir is the index of the deepest directory.
				for dir in range(-1, -len(os.path.split(dirname))):
					if os.listdir(dirname):
						break
					else:
						os.rmdir(dirname)
						del(dirname[dir])
				logging.warning('VERIFY_WRITES is enabled, and the verification was failed. The file has been removed.')
		else:
			logging.debug('VERIFY_WRITES is disabled, so the write verification was skipped.')			

	except:
		logging.error('Exception occurred.', exc_info=True)

	if successful:
		return filename
	return False

def check_status(status_code):
	#Check if the server gave us the file.
	if status_code == requests.codes['ok']:
		#Log that the server game us the file. It says 'completed successfully' but that just describes the download process, not if the file itself is valid.
		logging.debug('Download from server completed successfully.')
	
	else:
		#Log that the server didn't us the file. The status code it returned will be logged.
		logging.warning('Download from server failed. The server returned status code ' + str(status_code) + '.')
	
	return status_code == requests.codes['ok']

def check_size(content, size):
	#Check the size of the download, if enabled. This provides a basic integrity check, and it is very quick.
	successful = (not CHECK_SIZE) or (len(content) == size)
	
	if successful:
		#If check size is enabled, log the results, if not log that it is disabled.

		if CHECK_SIZE:
			#The download is the right size.
			logging.debug('Download has the proper size of ' + str(size) + '.')
		else:
			#The download's size was not checked.
			logging.debug('Download size was not checked, but the file should have had a size of ' + str(size) + '.')

	else:
		#The download failed the size check. This will be logged.
		logging.warning('Download failed the size check. it should have had a size of ' + str(size) + ' but it actually had a size of ' + str(len(content)) + '.')

	return successful

def check_sha_1_hash(content, sha_1_hash):
	#Check the SHA-1 of the download, if enabled. This provides a integrity check.
	successful = not CHECK_SHA_1_HASH
	
	if not successful:
		#CHECK_SHA_1_HASH is enabled, so the SHA-1 hash will be checked, and the results logged.

		hash = hashlib.sha1(content).hexdigest().upper()

		if hash == sha_1_hash:
			#The download's SHA-1 hash is correct.
			logging.debug('Download has the proper SHA-1 hash of ' + sha_1_hash + '.')
		else:
			#The download failed the SHA-1 hash check. This will be logged.
			logging.warning('Download failed the SHA-1 hash check. it should have had a SHA-1 hash of ' + sha_1_hash + ' but it actually had a SHA-1 hash of ' + hash + '.')
		
		successful = (hash == sha_1_hash)
		
	else:
		#The download's SHA-1 hash was not checked.
		logging.debug('Download SHA-1 hash was not checked, but the file should have had a SHA-1 hash of ' + sha_1_hash + '.')

	return successful

def check_sha_256_hash(content, sha_256_hash):
	#Check the SHA-256 of the download, if enabled. This provides a integrity check.
	successful = not CHECK_SHA_256_HASH
	
	if not successful:
		#CHECK_SHA_256_HASH is enabled, so the SHA-256 hash will be checked, and the results logged.

		hash = hashlib.sha256(content).hexdigest().upper()

		if hash == sha_256_hash:
			#The download's SHA-256 hash is correct.
			logging.debug('Download has the proper SHA-256 hash of ' + sha_256_hash + '.')
		else:
			#The download failed the SHA-256 hash check. This will be logged.
			logging.warning('Download failed the SHA-256 hash check. it should have had a SHA-256 hash of ' + sha_256_hash + ' but it actually had a SHA-256 hash of ' + hash + '.')
		
		successful = (hash == sha_256_hash)
		
	else:
		#The download's SHA-256 hash was not checked.
		logging.debug('Download SHA-256 hash was not checked, but the file should have had a SHA-256 hash of ' + sha_256_hash + '.')

	return successful

def download_loop(mod_file, repository):
	#version is a version of the mod, and mod_file is the data for that version, including the download url, size, hashes, etc.
	logging.info('Getting version ' + mod_file['version'] + ' from ' + mod_file['download'] + '\t.')

	#Don't download anything if downloads are disabled.
	if NO_DOWNLOAD:
		if zip_check := check_for_zip(get_mod_save_path(mod_file, repository)):
			logging.debug('Downloads are disabled, but a .zip file was found at ' + zip_check + '.')
			return zip_check
		logging.debug('Downloads are disabled, and no .zip file was found.')
		return False

	#Download it.
	for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
		if filename := download_file(mod_file, repository):
			#The download succeeded. This will be logged.
			logging.info('Download succeeded on attempt ' + str(attempt) + '.')
			return filename
		elif attempt != DOWNLOAD_ATTEMPTS:
			#The download failed. This will be logged, and it will be tried again.
			logging.warning('Download failed. Retrying. Attempt ' + str(attempt + 1) + '.')
		else:
			#The download failed. This will be logged, and not be retried.
			logging.error('Download failed. No more attempts will be made.')
			return False

def load_repos():
	#Get the url of the main CKAN metadata repo.
	logging.info('Using main repo ' + CKAN_MAIN_REPO_URL + '\t.')

	#Download the main repo .tar.gz file.
	r = requests.get(CKAN_MAIN_REPO_URL)
	memory_buffers = [io.BytesIO(r.content)]
	ckan_main_repo_tarfile = tarfile.open('r', fileobj=memory_buffers[-1])
	ckan_repo_tarfiles = {}

	repositories = None

	#Check if it can find other repos in the main one.
	for tarinfo in ckan_main_repo_tarfile.getmembers():
		if (os.path.basename(tarinfo.name) == 'repositories.json') and (tarinfo.isfile()):
			tf = ckan_main_repo_tarfile.extractfile(tarinfo)
			logging.info('repositories.json was found.')
			repositories = json.load(tf)['repositories']
			break

	#If it found the repos file, download those repos too.
	if repositories:
		for repository in repositories:
			if repository['uri'] == CKAN_MAIN_REPO_URL:
				ckan_repo_tarfiles[repository['name']] = ckan_main_repo_tarfile
				logging.info('The main repository is named ' + repository['name'] + '.')
			else:
				r = requests.get(repository['uri'])
				memory_buffers.append(io.BytesIO(r.content))
				ckan_repo_tarfiles[repository['name']] = tarfile.open('r', fileobj=memory_buffers[-1])
				logging.info('Found another repository named ' + repository['name'] + '.')
	else:
		#It didn't find the repositories.json, so it will call the repo 'unknown_repo'.
		logging.info('No repositories.json was found. It will be called unknown_repo.')
		ckan_repo_tarfiles['unknown_repo'] = ckan_main_repo_tarfile
	
	return [ckan_repo_tarfiles, memory_buffers]

def download_mod_repos(ckan_repo_tarfiles):
	#Download all of the avalible repos.
	for repository, ckan_repo in ckan_repo_tarfiles.items():
		#Print the repo it will download.
		logging.info('Downloading ' + repository + '.')

		#Set the .tar.gz output file location.
		filename = pathvalidate.sanitize_filepath(os.path.join(SAVE_PATH, 'repositories', (repository + '.tar.gz')), replacement_text='_')
		os.makedirs(os.path.dirname(filename), exist_ok=True)
		if os.path.exists(filename):
			os.remove(filename)
		repo_tarfile = tarfile.open(filename, 'x:gz')

		#Find all of the files in the repo .tar.gz file.
		for tarinfo in ckan_repo.getmembers():
			if tarinfo.isfile():
				tf = ckan_repo.extractfile(tarinfo)

				#If it is a CKAN file, it is a mod that will be downloaded, then the download location will be changed to the local repo.
				if os.path.splitext(tarinfo.name)[-1] == '.ckan':
					mod_file = json.load(tf)
					tf.seek(0)

					if filename := download_loop(mod_file, repository):

						patched_bytes = tf.read().replace(mod_file['download'].encode('utf-8'), filename.replace(os.path.sep, '/').replace(SAVE_PATH, LOCAL_DOWNLOAD_ROOT).encode('utf-8'))
						tmp = io.BytesIO(patched_bytes)

						tarinfo.size = len(patched_bytes)

						repo_tarfile.addfile(tarinfo, fileobj=tmp)

						tmp.close()

				#If it is the repositories.json file, it will be edited to change the paths to the LOCAL_DOWNLOAD_ROOT.
				elif os.path.basename(tarinfo.name) == 'repositories.json':
					repositories_file = json.load(tf)

					for repositories_file_section in repositories_file['repositories']:

						repositories_file_section_filename = pathvalidate.sanitize_filepath(os.path.join(SAVE_PATH, 'repositories', (repositories_file_section['name'] + '.tar.gz')), replacement_text='_')

						patched_bytes = tf.read().replace(repositories_file_section['uri'].encode('utf-8'), repositories_file_section_filename.replace(os.path.sep, '/').replace(SAVE_PATH, LOCAL_DOWNLOAD_ROOT).encode('utf-8'))
						tmp = io.BytesIO(patched_bytes)

						tarinfo.size = len(patched_bytes)

						repo_tarfile.addfile(tarinfo, fileobj=tmp)

						tmp.close()

				#If it is neither, copy it to the new repo file.
				else:
					repo_tarfile.addfile(tarinfo, fileobj=tf)

		#Save the .tar.gz file and close the .tar.gz in memory.
		repo_tarfile.close()
		ckan_repo.close()

def close_memory_buffers(memory_buffers):
	for memory_buffer in memory_buffers:
		memory_buffer.close()

def load_args():
	global DRY_RUN, SAVE_PATH, DOWNLOAD_ATTEMPTS, LOG_FILE_NAME, VERIFY_WRITES, LOCAL_DOWNLOAD_ROOT, CKAN_MAIN_REPO_URL, NO_DOWNLOAD

	#Load arguments.
	parser = argparse.ArgumentParser(description='CKAN Downloader Options.')
	parser.add_argument('--dry-run', help='Don\'t save any downloaded files.', action='store_true')
	parser.add_argument('--save-path', help='Where to save the files, defaults to \'' + SAVE_PATH + '\'.')
	parser.add_argument('--download-attempts', help='How many download attempts to make, defaults to \'' + str(DOWNLOAD_ATTEMPTS) + '\'.', type=int)
	parser.add_argument('--log-file-name', help='Where to save the log file, defaults to \'' + LOG_FILE_NAME + '\'.')
	parser.add_argument('--disable-verify-writes', help='Disables write verification.', action='store_false', dest='verify_writes')
	parser.add_argument('--local-download-root', help='Where your local repo will be located, defaults to \'' + LOCAL_DOWNLOAD_ROOT + '\'.')
	parser.add_argument('--ckan-main-repo-url', help='What CKAN repo to use, defaults to \'' + CKAN_MAIN_REPO_URL + '\'.')
	parser.add_argument('--no-download', help='Disables downloading and verifying mod files. Useful for changing CKAN metadata files.', action='store_true')
	args = parser.parse_args()

	#Put arguments to variables.
	DRY_RUN = args.dry_run

	if args.save_path:
		SAVE_PATH = args.save_path

	if args.download_attempts:
		DOWNLOAD_ATTEMPTS = args.download_attempts

	if args.log_file_name:
		LOG_FILE_NAME = args.log_file_name

	VERIFY_WRITES = args.verify_writes

	if args.local_download_root:
		LOCAL_DOWNLOAD_ROOT = args.local_download_root

	if args.ckan_main_repo_url:
		CKAN_MAIN_REPO_URL = args.ckan_main_repo_url
	
	NO_DOWNLOAD = args.no_download

def main():
	ti = time.time()

	load_args()

	logging_setup()

	logging.info('CKAN Downloader: A tool to download all of The Comprehensive Kerbal Archive Network (https://github.com/KSP-CKAN/CKAN).')

	repos_data = load_repos()
	download_mod_repos(repos_data[0])
	close_memory_buffers(repos_data[1])

	logging.info('Done. The download took ' + str(time.time() - ti) + ' seconds.')

if __name__ == '__main__':
	main()