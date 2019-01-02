/*
 * @Author: Gaurav Mishra
 * @Date:   2018-12-30 19:15:04
 * @Last Modified by:   Gaurav Mishra
 * @Last Modified time: 2018-12-31 12:38:43
 */

var express = require('express'); // Application Framework
var app = express(); // Decalring application instance
var url = require('url'); // For parsing URL
var fs = require('fs'); // For file system access
var bodyParser = require('body-parser'); // For parsing or decoding body
var exec = require('child_process').exec; // For executing system commands such as wpscan
var multiparty = require('multiparty'); // For parsing form fields such as file, fields, etc
var validUrl = require('valid-url'); // For validating URL
var Promise = require('bluebird'); // For promise
const https = require('https'); // For implementing SSL/TLS
var cron = require('node-cron'); // For validating cron rules
var schedule = require('node-schedule'); // For scheduling jobs and maintaining a history of cron jobs
var cookieParser = require('cookie-parser');
var session = require('express-session');
var helmet = require('helmet');

/* 
Certificate and Key generation commands:
========================================
openssl genrsa -out ssl/localhost.key 2048
openssl req -new -x509 -key ssl/localhost.key -out ssl/localhost.cert -days 3650 -subj /CN=localhost
*/

var options = {
    key: fs.readFileSync('./ssl/localhost.key'),
    cert: fs.readFileSync('./ssl/localhost.cert'),
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

server.listen(1337, function() {
    console.log('Server has started listening on port ' + 1337);
});

app.use(cookieParser());
// initialize express-session to allow us track the logged-in user across sessions.
var hour = 3600000;
app.use(session({
    key: 'user_sid',
    secret: 'expedia_123',
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
        if (username === "admin" && password === "admin") {
            req.session.user = username;
            res.redirect('/main');
        } else {
            res.redirect('/login');
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
            if (fields.scanUrl.toString().trim() !== "" && files.url_list[0].size > 0) {
                return res.send("Please supply ethier a URL or a file");
            }
            // When URL is supplied as an input
            else if (fields.scanUrl.toString().trim() !== "" && files.url_list[0].size === 0) {
                if (validUrl.isUri(fields.scanUrl.toString().trim())) {
                    try {
                        var scanUrl = url.parse(fields.scanUrl.toString().trim(), true);
                        startSingleScan(scanUrl, res).then(function(result) {
                            if (result) {
                                console.log("URL Scanned successfully");
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
            else if (files.url_list[0].size > 0 && (fields.scanUrl.toString().trim() == "" || fields.scanUrl.toString().trim() == undefined)) {

                if (files.url_list[0]['headers']['content-type'] == "text/plain" && files.url_list[0]["originalFilename"].split('.').pop() == "txt" && files.url_list[0].size <= 2097152) {
                    res.status(200).send("Scan is running in the background. Go take a coffee!<br>Scan history will be updated automatically.");
                    var filePath = files.url_list[0].path;
                    var data = fs.readFileSync(filePath, 'utf8');
                    var urlList = data.split('\n');
                    var promises = [];

                    for (var i = 0; i < urlList.length; i++) {
                        if (validUrl.isUri(urlList[i])) {
                            var urlStr = url.parse(urlList[i], true);
                            promises.push(startScan(urlStr, res));
                        } else {
                            //console.log("Invalid URI found: " + urlList[i]);
                        }
                    }

                    Promise.all(promises).then(function(result) {
                        console.log("List scanned successfully!");
                    }, function(err) {
                        console.log("What went wrong?" + err);
                    });
                } else if (files.url_list[0]['headers']['content-type'] == "text/plain" && files.url_list[0].size > 2097152) {
                    return res.status(200).send("File size should not exceed 2 MB.");
                } else {
                    return res.status(200).send("Only text files are allowed");
                }

            }
            // When server could not understand the input properly
            else {
                return res.send("Please supply an input");
            }

        });
        form.on('close', function() {
            console.log('Upload completed!');
        });
    } else {
        res.redirect('/login');
    }
});

function startSingleScan(scanUrl, res) {
    console.log("Scan started on URI: " + scanUrl.href);
    var timestamp = new Date().getTime();
    var filename = scanUrl.hostname + "_" + timestamp + ".json";
    var cmd = 'wpscan --format=json -o data/scan_results/' + filename + ' --url=' + scanUrl.href + '|| :';
    // Using ` || : ` as a hack to return 0 exit code because otherwise wpscan returns non-zero exit code 
    // which makes node js to think command failed to run. ` echo $? ` is used to check exit code

    return new Promise(function(resolve, reject) {
        child = exec(cmd, null, function(error, stderr, stdout) {

            var resultObj = JSON.parse(fs.readFileSync("./data/scan_results/" + filename, "utf8"));
            if (resultObj.scan_aborted != undefined) {
                res.status(200).send(resultObj.scan_aborted);
                resolve(false);
            } else {

                var result_details = {
                    "hostname": scanUrl.hostname,
                    "timestamp": timestamp,
                    "filename": filename
                };
                var obj = JSON.parse(fs.readFileSync("./data/scan_history.json", "utf8"));
                obj.scan_history.push(result_details);
                fs.writeFileSync("./data/scan_history.json", JSON.stringify(obj), function(err) {
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
    console.log("Scan started on URI: " + scanUrl.href);
    var timestamp = new Date().getTime();
    var filename = scanUrl.hostname + "_" + timestamp + ".json";
    var cmd = 'wpscan --format=json -o data/scan_results/' + filename + ' --url=' + scanUrl.href + '|| :';
    // Using ` || : ` as a hack to return 0 exit code because otherwise wpscan returns non-zero exit code 
    // which makes node js to think command failed to run. ` echo $? ` is used to check exit code
    return new Promise(function(resolve, reject) {
        child = exec(cmd, null, function(error, stderr, stdout) {

            var resultObj = JSON.parse(fs.readFileSync("./data/scan_results/" + filename, "utf8"));
            if (resultObj.scan_aborted != undefined) {
                // Do Nothing
            } else {

                var result_details = {
                    "hostname": scanUrl.hostname,
                    "timestamp": timestamp,
                    "filename": filename
                };
                var obj = JSON.parse(fs.readFileSync("./data/scan_history.json", "utf8"));
                obj.scan_history.push(result_details);
                fs.writeFileSync("./data/scan_history.json", JSON.stringify(obj), function(err) {
                    if (err) {
                        console.log("Error: " + err);
                    }
                });
            }
            resolve(true);
        });

    });

}

app.get("/fetch/scheduled/history", function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        var data = JSON.parse(fs.readFileSync("./data/scheduled_scans.json", "utf-8"));
        return res.status(200).send(data);
    } else {
        res.redirect('/login');
    }
});

var currentCount = JSON.parse(fs.readFileSync("./data/scheduled_scans.json", "utf-8")).total;

app.post("/schedule", function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        var second = req.body.second.trim(),
            minute = req.body.minute.trim(),
            hour = req.body.hour.trim(),
            day = req.body.day.trim(),
            dayOfMonth = req.body.dayOfMonth.trim(),
            dayOfWeek = req.body.dayOfWeek.trim(),
            scanUrl = req.body.scheduleUrl.trim(),
            scheduleRule = second + " " + minute + " " + hour + " " + day + " " + dayOfMonth + " " + dayOfWeek,
            valid;
        if (scanUrl == "") {
            return res.status(200).send('{"message":"Please enter a URL.", "statusCode": 0}');
        } else if (scanUrl !== "") {
            try {
                var Url = url.parse(scanUrl, true);
                valid = cron.validate(scheduleRule.trim());
                if (valid) {
                    let startTime = new Date();

                    var schedule_details = { "rule": scheduleRule.trim(), "startTime": startTime, "scan_nubmer": ++currentCount, "hostname": Url.hostname, "Url": Url.href };
                    var obj = JSON.parse(fs.readFileSync("./data/scheduled_scans.json", 'utf8'));
                    obj.scheduled_scans.push(schedule_details);
                    obj.total = currentCount;
                    fs.writeFileSync("./data/scheduled_scans.json", JSON.stringify(obj), function() {
                        if (err) {
                            console.log("Error: " + err);
                        }
                    });

                    var task = schedule.scheduleJob({ start: startTime, rule: scheduleRule }, function() {
                        startScan(Url, res).then(function(result) {
                            if (result)
                                console.log("Scheduled scan completed successfully");
                        });
                    });
                    return res.status(200).send('{"message":"Scan has been scheduled.","statusCode":100}');
                } else {
                    return res.status(200).send('{"message":"Invalid cron fields entered. Please retry","statusCode":400}');
                }

            } catch (err) {
                return res.status(200).send('{"message":"Unable to parse the URL.", "statusCode": 200}');
            }
        } else {
            return res.status(200).send('{"message":"I don\'t understand the input.", "statusCode": 300}');
        }
    } else {
        res.redirect('/login');
    }
});


function reinitializeScheduledScans() {
    console.log("Re-initializing Scheduled Scans");
    var obj = JSON.parse(fs.readFileSync("./data/scheduled_scans.json", 'utf8'));
    for (let i = 0; i < obj.scheduled_scans.length; i++) {
        var task = schedule.scheduleJob({ start: obj.scheduled_scans[i].startTime, rule: obj.scheduled_scans[i].rule }, function(data) {
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
            var obj = JSON.parse(fs.readFileSync("./data/scan_results/" + req.query.file, 'utf8'));
            res.send(obj);
            res.end();
        } catch (err) {
            res.redirect('/');
        }
    } else {
        res.redirect('/login');
    }
});

app.get("/fetch/scan/history", function(req, res) {
    if (req.session.user && req.cookies.user_sid) {
        var obj = JSON.parse(fs.readFileSync("./data/scan_history.json", 'utf8'));
        res.send(obj);
        res.end();
    } else {
        res.redirect('/login');
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