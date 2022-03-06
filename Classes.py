import glob
import os
import sys

from polyswarm_api.api import PolyswarmAPI

api_key = "585f5ebcf40d7e7d2fccc33c3a8551a2"

api = PolyswarmAPI(key=api_key)


class Path:
    def __init__(self, directory, extension):
        self.directory = directory
        self.extension = extension
        self.extension = "*"

    def find_files(self):
        os.chdir(f'{self.directory}')
        for file in glob.glob(f"*.{self.extension}"):
            print(file)

    def remove(self):
        pass


p = Path(input("Enter a directory you would like to examine for the file types? If you want a full PC search, "
               "just hit enter! "),
         input("Please input the file extension that you would like to see (txt,docx,xlsx,csv,etc.) or hit enter"
               " for any file extension: "))
p.find_files()

question = input("Would you like to backup any of these files: ")

FILE = p.directory

positives = 0
total = 0

instance = api.submit(FILE)
result = api.wait_for(instance)

if result.failed:
    print(f'Failed to get results')
    sys.exit()

print('Engine Assertions:')
for assertion in result.assertions:
    if assertion.verdict:
        positives += 1
    total += 1
    print('\tEngine {} asserts {}'.format(assertion.author_name, 'Malicious' if assertion.verdict else 'Benign'))

print(f'Positives: {positives}')
print(f'Total: {total}')
print(f'PolyScore: {result.polyscore}\n')

print(f'sha256: {result.sha256}')
print(f'sha1: {result.sha1}')
print(f'md5: {result.md5}')
print(f'Extended type: {result.extended_type}')
print(f'First Seen: {result.first_seen}')
print(f'Last Seen: {result.last_seen}\n')

print(f'Permalink: {result.permalink}')
