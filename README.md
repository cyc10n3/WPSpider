# WPScan Web Interface
A centralised dashboard for running and scheduling WordPress scans powered by wpscan. It has the ability to show scan history and result in user-friendly format.

## Key Features

```
* Performs scan for single or multiple WordPress applications asynchronously
* Supports both on demand and scheduled scans (like a cron job)
* Cross-platform application
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
![#f03c15](https://placehold.it/15/f03c15/000000?text=+) `It is highly recommended to change the login password by modifying server.js`[`file`](https://github.com/cyc10n3/WPScan_Web_Interface/blob/master/server.js#L93).

## Screenshots

#### Login
![Login](/static/screenshots/1.png?raw=true "Login")

#### Dashboard: On-demand Scan
![Dashboard: On-demand Scan](/static/screenshots/2.png?raw=true "Dashboard: On-demand Scan")

#### Dashboard: Schedule Scan
![Dashboard: Schedule Scan](/static/screenshots/3.png?raw=true "Dashboard: Schedule Scan")

#### Scan Report
![Scan Report](/static/screenshots/4.png?raw=true "Scan Report")

## Authors

* **Gaurav Mishra** - *Initial work* - gmishra010@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
