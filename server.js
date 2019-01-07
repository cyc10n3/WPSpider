/*
 * @Author: Gaurav Mishra
 * @Date:   2018-12-30 19:15:04
 * @Last Modified by:   Gaurav Mishra
 * @Last Modified time: 2019-01-07 11:37:01
 */

var express = require('express');
var app = express();
var url = require('url');
var fs = require('fs');
var bodyParser = require('body-parser');
var exec = require('child_process').exec;
var multiparty = require('multiparty');
var validUrl = require('valid-url');
var Promise = require('bluebird');
const https = require('https');
var cron = require('node-cron');
var schedule = require('node-schedule');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var helmet = require('helmet');
var csrf = require('csurf')

var contextPath = "./";

/* 
Certificate and Key generation commands:
========================================
openssl genrsa -out ssl/localhost.key 2048
openssl req -new -x509 -key ssl/localhost.key -out ssl/localhost.cert -days 3650 -subj /CN=localhost
*/

var options = {
    key: fs.readFileSync(contextPath + "ssl/localhost.key"),
    cert: fs.readFileSync(contextPath + "ssl/localhost.cert"),
    requestCert: false,
    rejectUnauthorized: false
};
var server = https.createServer(options, app);
app.use(helmet());
app.disable('x-powered-by');
app.use(express.static(__dirname + '/static/'));
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(cookieParser());
app.use(csrf({ cookie: true }));
app.use(function(err, req, res, next) {
    if (err.code !== 'EBADCSRFTOKEN') return next(err);

    // handle CSRF token errors here
    res.status(403);
    res.send('Invalid CSRF Token. Please refresh the page.');
})

server.listen(1337, function() {
    console.log('Server has started listening on port ' + 1337);
});

var appConfig = JSON.parse(fs.readFileSync(contextPath + "config.json", "utf8"));

// initialize express-session to allow us track the logged-in user across sessions.
var hour = 3600000;
app.use(session({
    key: 'user_sid',
    secret: appConfig.session_secret,
    resave: true,
    saveUninitialized: true,
    rolling: true,
    cookie: {
        secure: true,
        httpOnly: true,
        maxAge: hour
    }
}));

// This middleware will check if user's cookie is still saved in browser and user is not set, then automatically log the user out.
// This usually happens when you stop your express server after login, your cookie still remains saved in the browser.
app.use((req, res, next) => {
    if (req.cookies.user_sid && !req.session.user) {
        res.clearCookie('user_sid');
    }
    next();
});

// middleware function to check for logged-in users
var sessionChecker = (req, res, next) => {
    if (req.session.user && req.cookies.user_sid) {
        res.redirect('/main');
    } else {
        res.redirect("/login");
    }
};

// route for user Login
app.route('/login')
    .get((req, res) => {
        res.sendFile(__dirname + '/static/templates/login.html');
    })
    .post((req, res) => {
        var username = req.body.username,
            password = req.body.password;
        if (username !== undefined && password !== undefined) {
            if (username.toString() === appConfig.login_creds.username && password.toString() === appConfig.login_creds.password) {
                req.session.user = username;
                res.status(200).send(true);
            } else if (username.toString().trim() === "" && password.toString().trim() === "") {
                res.status(403).send("Please supply username and password.");
            } else if (username.toString().trim() === "" || password.toString().trim() === "") {
                res.status(403).send("Please supply both username and password.");
            } else {
                res.status(403).send("Invalid username or password.");
            }
        } else {
            res.status(403).send("Request has been tampered.");
        }

    });

// route for user logout
app.get('/logout', (req, res) => {
    if (req.session.user && req.cookies.user_sid) {
        req.session.destroy();
        res.clearCookie('user_sid');
        res.redirect('/login');
    } else {
        res.redirect('/login');
    }
});

app.get('/', sessionChecker, function(req, res) {
    fs.readFile("static/templates/login.html", function(err, data) {
        if (err) {
            res.writeHead(404, {
                'Content-Type': 'text/html'
            });
            return res.end("404 Not Found");
        }
        res.writeHead(200, {
            'Content-Type': 'text/html'
        });
        res.write(data);
        return res.end();
    });
});

app.get('/csrfToken', function(req, res) {
    return res.status(200).send({ csrfToken: req.csrfToken() });
});

var child;

app.get('/main', function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        fs.readFile("static/templates/main.html", function(err, data) {
            if (err) {
                res.writeHead(404, {
                    'Content-Type': 'text/html'
                });
                return res.end("404 Not Found");
            }
            res.writeHead(200, {
                'Content-Type': 'text/html'
            });
            res.write(data);
            return res.end();
        });
    } else {
        res.redirect('/login');
    }
});


app.post('/scan', function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        var form = new multiparty.Form();
        form.parse(req, function(err, fields, files) {
            // When both the inputs are supplied
            if (fields.scanUrl !== undefined && files.url_list !== undefined) {
                var _url = fields.scanUrl.toString().trim();
                var fileContentType = files.url_list[0]['headers']['content-type'];
                var fileExtension = files.url_list[0]["originalFilename"].split('.').pop();
                var fileSize = files.url_list[0].size;
                var filePath = files.url_list[0].path;
                if (_url !== "" && fileSize > 0) {
                    return res.send("Please supply ethier a URL or a file");
                }
                // When URL is supplied as an input
                else if (_url !== "" && fileSize === 0) {
                    if (validUrl.isHttpUri(_url) || validUrl.isHttpsUri(_url)) {
                        try {
                            var scanUrl = url.parse(_url, true);
                            startSingleScan(scanUrl, res).then(function(result) {
                                if (result) {
                                    console.log("URL Scanned successfully: " + scanUrl.href);
                                    res.status(200).send("URL Scanned successfully");
                                }
                            });
                        } catch (err) {
                            return res.status(200).send("Unable to parse the URL");
                        }
                    } else {
                        return res.status(200).send("Invalid URL Supplied");
                    }
                }
                // When File is supplied as an input
                else if (fileSize > 0 && _url == "") {
                    var i;
                    if (fileContentType == "text/plain" && fileExtension == "txt" && fileSize <= 2097152) {
                        res.status(200).send("Scan is running in the background. Go take a coffee!<br>Scan history will be updated automatically.");
                        var data = fs.readFileSync(filePath, 'utf8');
                        var urlList = data.split('\n');
                        var promises = [];
                        var urlListLength = urlList.length;
                        for (i = 0; i < urlListLength; i++) {
                            if (validUrl.isHttpUri(urlList[i]) || validUrl.isHttpsUri(urlList[i])) {
                                var urlStr = url.parse(urlList[i], true);
                                promises.push(startScan(urlStr, res));
                            }
                        }
                        Promise.all(promises).then(function(result) {
                            console.log("List scanned successfully!");
                        }, function(err) {
                            console.log("What went wrong?" + err);
                        });
                    } else if (fileContentType == "text/plain" && fileSize > 2097152) {
                        return res.status(200).send("File size should not exceed 2 MB.");
                    } else {
                        return res.status(200).send("Only text files are allowed");
                    }
                }
                // When server could not understand the input properly
                else {
                    return res.send("Please supply an input");
                }
            } else {
                return res.send("Request has been tampered");
            }

        });
        form.on('close', function() {
            //console.log('Upload completed!');
        });
    } else {
        res.redirect('/login');
    }
});

function startSingleScan(scanUrl, res) {
    console.log("Scan started on: " + scanUrl.protocol + '//' + scanUrl.hostname);
    var timestamp = new Date().getTime();
    var filename = scanUrl.hostname + "_" + timestamp + ".json";
    var cmd = 'wpscan --format=json --ignore-main-redirect -o data/scan_results/' + filename + ' --url=' + scanUrl.protocol + '//' + scanUrl.hostname + '/ || :';
    // Using ` || : ` as a hack to return 0 exit code because otherwise wpscan returns non-zero exit code 
    // which makes node js to think command failed to run. ` echo $? ` is used to check exit code

    return new Promise(function(resolve, reject) {
        child = exec(cmd, null, function(error, stderr, stdout) {
            var resultObj = JSON.parse(fs.readFileSync(contextPath + "data/scan_results/" + filename, "utf8"));
            if (resultObj.scan_aborted !== undefined) {
                console.log("Scan failed for: " + scanUrl.protocol + '//' + scanUrl.hostname);
                try {
                    fs.unlink(contextPath + "data/scan_results/" + filename, (err) => {
                        if (err) throw err;
                    });
                } catch (err) {

                }
                console.log("Reason: " + resultObj.scan_aborted);
                res.status(200).send(resultObj.scan_aborted);
                resolve(false);
            } else {
                var result_details = {
                    "hostname": scanUrl.hostname,
                    "timestamp": timestamp,
                    "filename": filename
                };
                var obj = JSON.parse(fs.readFileSync(contextPath + "data/scan_history.json", "utf8"));
                obj.scan_history.unshift(result_details);
                fs.writeFileSync(contextPath + "data/scan_history.json", JSON.stringify(obj), function(err) {
                    if (err) {
                        console.log("Error: " + err);
                    }
                });
                resolve(true);
            }
        });
    });
}

function startScan(scanUrl, res) {
    console.log("Scan started on: " + scanUrl.protocol + '//' + scanUrl.hostname);
    var timestamp = new Date().getTime();
    var filename = scanUrl.hostname + "_" + timestamp + ".json";
    var cmd = 'wpscan --format=json --ignore-main-redirect -o data/scan_results/' + filename + ' --url=' + scanUrl.protocol + '//' + scanUrl.hostname + '/ || :';
    // Using ` || : ` as a hack to return 0 exit code because otherwise wpscan returns non-zero exit code 
    // which makes node js to think command failed to run. ` echo $? ` is used to check exit code
    return new Promise(function(resolve, reject) {
        child = exec(cmd, null, function(error, stderr, stdout) {
            try {
                var resultObj = JSON.parse(fs.readFileSync(contextPath + "data/scan_results/" + filename, "utf8"));
                if (resultObj.scan_aborted !== undefined) {
                    console.log("Scan failed for: " + scanUrl.protocol + '//' + scanUrl.hostname);
                    try {
                        fs.unlink(contextPath + "data/scan_results/" + filename, (err) => {
                            if (err) throw err;
                        });
                    } catch (err) {

                    }
                    console.log("Reason: " + resultObj.scan_aborted);
                } else {
                    var result_details = {
                        "hostname": scanUrl.hostname,
                        "timestamp": timestamp,
                        "filename": filename
                    };
                    var obj = JSON.parse(fs.readFileSync(contextPath + "data/scan_history.json", "utf8"));
                    obj.scan_history.unshift(result_details);
                    console.log("Scan successfully completed for: " + result_details.hostname);
                    try {
                        fs.writeFileSync(contextPath + "data/scan_history.json", JSON.stringify(obj), function(err) {
                            if (err) {
                                console.log("Error: " + err);
                            }
                        });
                    } catch (err) {
                        console.log("Error writing to file: " + err);
                    }
                }
            } catch (err) {
                console.log("Error reading file: " + err);
            }
            resolve(true);
        });
    });
}

app.get("/fetch/scheduled/history", function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        var data = JSON.parse(fs.readFileSync(contextPath + "data/scheduled_scans.json", "utf-8"));
        return res.status(200).send(data);
    } else {
        res.redirect('/login');
    }
});

var currentCount = JSON.parse(fs.readFileSync(contextPath + "data/scheduled_scans.json", "utf-8")).total;

app.post("/schedule", function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        var reqBody = req.body;
        var second = reqBody.second ? reqBody.second : "",
            minute = reqBody.minute,
            hour = reqBody.hour,
            day = reqBody.day,
            dayOfMonth = reqBody.dayOfMonth,
            dayOfWeek = reqBody.dayOfWeek,
            scanUrl = reqBody.scheduleUrl;
        var isRequestValid = (minute !== undefined) && (hour !== undefined) && (day !== undefined) && (dayOfMonth !== undefined) && (dayOfWeek !== undefined) && (scanUrl !== undefined);
        if (isRequestValid) {
            var scheduleRule = second.trim() + " " + minute.trim() + " " + hour.trim() + " " + day.trim() + " " + dayOfMonth.trim() + " " + dayOfWeek.trim(),
                valid;
            scanUrl = scanUrl.trim();
            if (scanUrl == "") {
                return res.status(400).send('{"message":"Please enter a URL.", "status": "failure"}');
            } else if (scanUrl !== "" && (validUrl.isHttpUri(scanUrl) || validUrl.isHttpsUri(scanUrl))) {
                try {
                    var Url = url.parse(scanUrl, true);
                    valid = cron.validate(scheduleRule.trim());
                    if (valid) {
                        let timestamp = new Date().getTime();;
                        var schedule_details = { "rule": scheduleRule.trim(), "timestamp": timestamp, "hostname": Url.hostname, "Url": Url.href };
                        var obj = JSON.parse(fs.readFileSync(contextPath + "data/scheduled_scans.json", 'utf8'));
                        obj.scheduled_scans.unshift(schedule_details);
                        obj.total = ++currentCount;
                        fs.writeFileSync(contextPath + "data/scheduled_scans.json", JSON.stringify(obj), function() {
                            if (err) {
                                console.log("Error: " + err);
                            }
                        });
                        var task = schedule.scheduleJob({ start: timestamp, rule: scheduleRule }, function() {
                            startScan(Url, res).then(function(result) {
                                if (result)
                                    console.log("Scheduled scan completed successfully");
                            });
                        });
                        return res.status(200).send('{"message":"Scan has been scheduled successfully.","status":"success"}');
                    } else {
                        return res.status(400).send('{"message":"Invalid cron fields entered. Please retry","status":"failure"}');
                    }
                } catch (err) {
                    return res.status(400).send('{"message":"Unable to parse the URL.", "status": "failure"}');
                }
            } else {
                return res.status(400).send('{"message":"Please enter a valid URL", "status": "failure"}');
            }
        } else {
            return res.status(400).send('{"message":"Request has been tampered.", "status": "failure"}');
        }
    } else {
        res.redirect('/login');
    }
});

function reinitializeScheduledScans() {
    console.log("Re-initializing Scheduled Scans");
    var obj = JSON.parse(fs.readFileSync(contextPath + "data/scheduled_scans.json", 'utf8'));
    for (let i = 0; i < obj.scheduled_scans.length; i++) {
        var task = schedule.scheduleJob({ start: obj.scheduled_scans[i].timestamp, rule: obj.scheduled_scans[i].rule }, function(data) {
            startScan(url.parse(obj.scheduled_scans[i].Url, true)).then(function(result) {
                if (result)
                    console.log("Scheduled scan completed successfully");
            });
        });
    }
}

reinitializeScheduledScans();

app.get("/report", function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        try {
            var hostname = req.query.hostname;
            var timestamp = req.query.timestamp;
            if (hostname !== undefined && timestamp !== undefined) {
                var obj = JSON.parse(fs.readFileSync(contextPath + "data/scan_history.json", 'utf8'));
                var i;
                var objLen = obj.scan_history.length;
                var scanHistory = obj.scan_history;
                for (i = 0; i < objLen; i++) {
                    if (scanHistory[i].hostname == hostname && scanHistory[i].timestamp == timestamp) {
                        var objResult = JSON.parse(fs.readFileSync(contextPath + "data/scan_results/" + scanHistory[i].filename, 'utf8'));
                        res.send(objResult);
                        res.end();
                        return;
                    }
                }
                if (i == objLen) {
                    res.redirect("/main");
                }
            } else {
                return res.status(400).send("Request has been tampered");
            }
        } catch (err) {
            res.redirect('/');
        }
    } else {
        res.redirect('/login');
    }
});

app.get("/fetch/scan/history", function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        var obj = JSON.parse(fs.readFileSync(contextPath + "data/scan_history.json", 'utf8'));
        res.send(obj);
        res.end();
    } else {
        res.redirect('/login');
    }
});

app.post("/delete/report", function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        try {
            var hostname = req.body.hostname;
            var timestamp = req.body.timestamp;
            if (hostname !== undefined && timestamp !== undefined) {
                var historyObj = JSON.parse(fs.readFileSync(contextPath + "data/scan_history.json", 'utf8'));
                var scanHistoryList = historyObj.scan_history;
                var historyLength = scanHistoryList.length;
                var i;
                for (i = 0; i < historyLength; i++) {
                    if (scanHistoryList[i].hostname === hostname && scanHistoryList[i].timestamp === parseInt(timestamp)) {
                        // Report deletion logic
                        var j = i;
                        fs.unlink(contextPath + "data/scan_results/" + scanHistoryList[i].filename, (err) => {
                            if (err) {
                                console.log("Failed to delete the report.");
                                return res.status(400).send("Failed to delete the report.");
                            } else {
                                console.log("Report successfully deleted. Updating scan history...");
                                historyObj.scan_history.splice(j, 1);
                                fs.writeFile(contextPath + "data/scan_history.json", JSON.stringify(historyObj), function(err) {
                                    if (err) {
                                        console.log("Failed to update scan history.");
                                    } else {
                                        console.log("Scan history updated successfully.");
                                        return res.status(200).send(true);
                                    }
                                });
                            }
                        });
                    }
                }
            } else {
                return res.status(400).send("Request has been tampered");
            }
        } catch (err) {

        }
    }
});

app.post("/delete/schedule", function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        try {
            var hostname = req.body.hostname;
            var timestamp = req.body.timestamp;
            if (hostname !== undefined && timestamp !== undefined) {
                var scheduleHistoryObj = JSON.parse(fs.readFileSync(contextPath + "data/scheduled_scans.json", 'utf8'));
                var scheduleHistoryList = scheduleHistoryObj.scheduled_scans;
                var scheduledHistoryLength = scheduleHistoryList.length;
                var i;
                for (i = 0; i < scheduledHistoryLength; i++) {
                    if (scheduleHistoryList[i].hostname === hostname && scheduleHistoryList[i].timestamp === parseInt(timestamp)) {
                        // Schedule deletion logic
                        scheduleHistoryObj.total -= 1;
                        scheduleHistoryObj.scheduled_scans.splice(i, 1);
                        fs.writeFile(contextPath + "data/scheduled_scans.json", JSON.stringify(scheduleHistoryObj), function(err) {
                            if (err) {
                                console.log("Failed to delete schedule.");
                            } else {
                                console.log("Schedule deleted successfully.");
                                return res.status(200).send(true);
                            }
                        });
                    }
                }
            } else {
                return res.status(400).send("Request has been tampered");
            }
        } catch (err) {

        }
    }
});

app.post('*', pageNotFound)

app.get('*', pageNotFound);

function pageNotFound(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        fs.readFile("static/templates/404.html", function(err, data) {
            res.writeHead(404, {
                'Content-Type': 'text/html'
            });
            res.write(data);
            return res.end();
        });
    } else {
        res.redirect('/login');
    }
}