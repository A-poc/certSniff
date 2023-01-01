# certSniff
CertSniff is a python based keyword sniffer, using the certstream certificate transparency log data stream, that monitors for domain certificate events containing a string of interest.

![image](https://user-images.githubusercontent.com/100603074/203795385-1ce9b0bd-da0e-446e-8abb-42ead14e7aeb.png)

# Install
```bash
git clone https://github.com/A-poc/certSniff;cd certSniff/;pip install -r requirements.txt
```

# Example
You can monitor live certificate transparency logs that contain any string within a keyword file.

`example.txt`
```
admin
test
dev
```

`python3 certSniff.py -f example.txt`
```

                              █████     █████████              ███     ██████     ██████ 
                             ░░███     ███░░░░░███            ░░░     ███░░███   ███░░███
  ██████   ██████  ████████  ███████  ░███    ░░░  ████████   ████   ░███ ░░░   ░███ ░░░ 
 ███░░███ ███░░███░░███░░███░░░███░   ░░█████████ ░░███░░███ ░░███  ███████    ███████   
░███ ░░░ ░███████  ░███ ░░░   ░███     ░░░░░░░░███ ░███ ░███  ░███ ░░░███░    ░░░███░    
░███  ███░███░░░   ░███       ░███ ███ ███    ░███ ░███ ░███  ░███   ░███       ░███     
░░██████ ░░██████  █████      ░░█████ ░░█████████  ████ █████ █████  █████      █████    
 ░░░░░░   ░░░░░░  ░░░░░        ░░░░░   ░░░░░░░░░  ░░░░ ░░░░░ ░░░░░  ░░░░░      ░░░░░     
Certificate Transparency Log Sniffer
-----------------------------------------------------------------------------------------
    
Using sniff words from [example.txt]
11/24/22 13:18:31 + aonecnameg.goce.workers.dev
11/24/22 13:18:31 + sbzvbzoompezxyu.southcentralus.atlas-test.cloudapp.azure.com
11/24/22 13:18:32 + admin-test.crystal.io
...
```
