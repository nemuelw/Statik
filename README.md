# Statik

Script to automate the static analysis of a potentially malicious sample

## Set-up

- Clone this repository

  ```
  git clone https://github.com/nemzyxt/Statik.git
  ```
  
- Navigate to the project directory and run :

  ```
  pip3 install -r requirements.txt
  ```

- Edit the config file to contain your VirusTotal API key instead

## Usage

```
python3 statik.py sample/mal
```

Onwards, replace 'sample/mal' with the file you would like to analyze
