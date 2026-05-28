import urllib.request, json, os

test_file = r'C:\Windows\System32\notepad.exe'
print(f'Testing with: {test_file} ({os.path.getsize(test_file)/1024:.1f} KB)')

boundary = 'QuarantineTest1234'
with open(test_file, 'rb') as f:
    file_data = f.read()

body = (
    '--' + boundary + '\r\n'
    'Content-Disposition: form-data; name="file"; filename="notepad.exe"\r\n'
    'Content-Type: application/octet-stream\r\n\r\n'
).encode() + file_data + ('\r\n--' + boundary + '--\r\n').encode()

req = urllib.request.Request(
    'http://localhost:5000/api/scan',
    data=body,
    headers={'Content-Type': 'multipart/form-data; boundary=' + boundary},
    method='POST'
)

resp = urllib.request.urlopen(req, timeout=60)
result = json.loads(resp.read())
print('Verdict:', result['report']['verdict'])
print('Confidence:', str(round(result['report']['confidence']*100, 1)) + '%')
print('YARA matches:', result['report']['yara_matches'])
print('Indicators:')
for ind in result['report']['indicators'][:8]:
    print('  [' + ind['severity'].upper() + '] ' + ind['text'])
