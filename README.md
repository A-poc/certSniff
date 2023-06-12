# certSniff
CertSniff is a python based keyword sniffer, using the certstream certificate transparency log data stream, that monitors for domain certificate events containing a string of interest.

<img width="642" alt="image" src="https://user-images.githubusercontent.com/100603074/222743482-2432f2b3-39af-4cc5-84e1-cb032d73e2a9.png">

# Install
```bash
git clone https://github.com/A-poc/certSniff;cd certSniff/;pip install -r requirements.txt
```

# Usage
```bash
python3 certSniff.py -f monitor.txt
```

# Example
You can monitor live certificate transparency logs that contain any string within a keyword file.

```
monitor.txt
├── admin
├── test
└── dev
```

`python3 certSniff.py -f monitor.txt`
```
╔═╗┌─┐┬─┐┌┬┐╔═╗┌┐┌┬┌─┐┌─┐
║  ├┤ ├┬┘ │ ╚═╗││││├┤ ├┤ 
╚═╝└─┘┴└─ ┴ ╚═╝┘└┘┴└  └  
Certificate Transparency Log Sniffer
-----------------------------------------------------------------------------------------
Using sniff words from [monitor.txt]

[03/03/23 14:16:45]:[aonecnameg.goce.workers.dev]
[03/03/23 14:16:45]:[csbzvbzoompezxyu.southcentralus.atlas-test.cloudapp.azure.com]
[03/03/23 14:16:45]:[admin-test.crystal.io]
[03/03/23 14:16:45]:[dev-chompy.qmo.io]
[03/03/23 14:16:45]:[backuptest.blacklightsupport.co.za]
...
```
