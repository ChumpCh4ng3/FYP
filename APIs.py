import sys

from polyswarm_api.api import PolyswarmAPI

api_key = "317b21cb093263b701043cb0831a53b9"

api = PolyswarmAPI(key=api_key)
# scan one file
FILE = 'C:\Users\super\Documents\University'

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
    print('\tEngine {} asserts {}'.format(assertion.author_name,'Malicious' if assertion.verdict else 'Benign'))

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