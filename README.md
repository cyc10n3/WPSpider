# WPScan-Web-Interface
Scan WordPress websites for security issues.

## Key Features

```
* Cross-platform application
* Provides centralized security dashboard for WordPress security scans
* Perform scan for single or multiple WordPress applications asynchronously
* View scan history and reports
* Supports both on demand and scheduled scans
```

## Security Features

```
* Authentication and Authorization checks have been implemented to prevent unauthorized access to the
  application and its services.
* Only requests with valid http/https URL are accepted
* Restricted file upload- Only text files with max-file size 2 MB are processed
* User will be automatically logged-out after 1 hour of inactivity
```

## How to Setup?

```
* Download and Install Node.js- https://nodejs.org/en/download/
* Install wpscan- https://wpscan.org/
* git clone https://github.com/cyc10n3/WPScan_Web_Interface.git
* cd  WPScan-Web-Interface
* npm install (for installing node modules or dependencies)
* npm start
* Open https://localhost:1337 in browser
* Login with default credentials (admin/admin)
```
## Authors

* **Gaurav Mishra** - *Initial work* - gmishra010@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
