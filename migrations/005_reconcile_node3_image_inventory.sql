UPDATE images
SET file_name = 'ubuntu-22.04-server-cloudimg-amd64.qcow2'
WHERE id = 'ubuntu-2204';

UPDATE images
SET file_name = 'ubuntu-24.04-server-cloudimg-amd64.qcow2',
    enabled = false
WHERE id = 'ubuntu-2404';
