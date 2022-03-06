import glob
import os
from polyswarm_api.api import PolyswarmAPI

api_key = "317b21cb093263b701043cb0831a53b9"

api = PolyswarmAPI(key=api_key)
FILE = '/home/user/malicious.bin'

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
    print('\tEngine {} asserts {}'.\
            format(assertion.author_name,
                   'Malicious' if assertion.verdict else 'Benign'))

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

# scan one URL
URL = 'https://polyswarm.io'

positives = 0
total = 0

instance = api.submit(URL, artifact_type='url')
result = api.wait_for(instance)

if result.failed:
    print(f'Failed to get results')
    sys.exit()

print('Engine Assertions:')
for assertion in result.assertions:
    if assertion.verdict:
        positives += 1
    total += 1
    print('\tEngine {} asserts {}'.\
            format(assertion.author_name,
                   'Malicious' if assertion.verdict else 'Benign'))

print(f'Positives: {positives}')
print(f'Total: {total}\n')


directory = input("Enter a directory you would like to examine for the file types? If you want a full PC search, "
                  "just hit enter! ")
extension = input("Please input the file extension that you would like to see (txt,docx,xlsx,csv,etc.) or hit enter"
                  " for any file extension: ")
# if extension == "":
#     extension = "*"
if directory != "":
    os.chdir(f'{directory}')
    for file in glob.glob(f"*.{extension}"):
        print(file)

else:
    pass

question = input("Out of any of these files you see, are there any that look unfamiliar, if so, would you like them "
                 "deleted? (Yes/No): ")

list_of_files = glob.glob(f"*.{extension}")
if question.lower() == "yes" or "y":
    for i in range(len(list_of_files)):
        print(f"{i + 1}:{list_of_files[i]}")

try:
    selection_for_deleting = int(input("Which of these would like to delete, select by number: "))
except ValueError:
    new_selection = int(input("Make sure you enter a number that corresponds to the file: "))
else:
    new_selection = selection_for_deleting

del_confirmation = input(f"Are you sure you want to delete {list_of_files[new_selection - 1]}?(Yes/No) ")
if del_confirmation.lower() == "yes" or "y":
    print(f"{list_of_files[new_selection - 1]} has been removed!\n")
    os.remove(list_of_files[new_selection - 1])
    list_of_files.remove(list_of_files[new_selection - 1])
    for i in range(len(list_of_files)):
        print(f"{i + 1}:{list_of_files[i]}")


