const express = require("express");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const mysql = require("mysql");
const session = require("express-session");
const passport = require("passport");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const mySQLsessionStore = require("express-mysql-session");
const nodemailer = require("nodemailer");
const Cryptr = require("cryptr");
const cryptr = new Cryptr('KeyforUserNameEncryPt');
const fs = require("fs");
const fileUpload = require("express-fileupload");

//DATABASE CONNECTIONS
const DBoptions = {
    host: "localhost",
    port: 3306,
    user: "akshat",
    password: "cheeseMomo",
    database: "prodex"
}

var connection = mysql.createConnection(DBoptions);
connection.connect((err) => {
    if (err) {
        console.log("Error in connecting to DB");
    } else {
        console.log("connected to DB ;-)");
    }
});

//MAILING SYSTEM
var transporter = nodemailer.createTransport({
    host: "172.16.2.30",
    secure: true,
    port: 8080,
    proxy: "http://18cs10002:sanjaymama@172.16.2.30:8080",
    service: "gmail",
    auth: {
        user: "akshat.prodexiitkgp@gmail.com",
        pass: "prodex@123"
    }
});

//STORING SESSION IN DB
var sessionStore = new mySQLsessionStore(DBoptions);

var app = express();

//PUG SETUP
app.set('view engine', 'pug');
app.set('views', './views');

//MIDDLEWARE SETUPS
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
//COOKIE SETUPS
app.use(session({
    secret: 'nhfdjJNFJHNjnhkjhjnHJhJHjnNJnJHgn',
    resave: false,
    store: sessionStore,
    saveUninitialized: false,
    //cookie: {secure : true}  //for https server
}));
//AUTHENTICATION SETUPS
app.use(passport.initialize());
app.use(passport.session());
app.use((req, res, next) => {
    res.authenticationStatus = req.isAuthenticated();
    next();
});
//PIC UPLOAD SETUPS
app.use(fileUpload());


//SCRIPTS SOURCE
app.get("/script/jquery.js", (req, res) => {
    res.sendFile(__dirname + "/scripts/jquery.js");
});


//HOME PAGE
app.get("/", (req, res) => {
    res.render("home.pug", { authenticationStatus: req.isAuthenticated(), aukaat: req.cookies.aukaat });
    console.log(req.isAuthenticated());
    console.log(req.cookies.aukaat);
});

//LOGIN PAGE
app.get("/login", (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect("/");
    } else {
        res.render("login", { authenticationStatus: req.isAuthenticated(), aukaat: req.cookies.aukaat });
    }
});

app.post("/login", (req, res) => {
    console.log(req.body);
    var username = req.body.username;
    var password = req.body.password;

    connection.query("SELECT * FROM user_data WHERE username = ?", [username], (err, rows, fields) => {
        if (err) {
            console.log(err.message);
            console.log("error in searching DB :-(");
        } else if (rows.length === 0) {
            res.send({ status: "not a valid username" });
        } else {
            bcrypt.compare(password, rows[0].password.toString(), (err, valid) => {
                if (err) {
                    console.log("not able to compare passwords :-(");
                } else if (valid) {
                    if (parseInt(rows[0].active_status)) {
                        req.login(username, (err) => {
                            res.cookie("aukaat", rows[0].aukaat)
                            res.send({ status: "success" });
                        });
                    } else {
                        res.send({ status: "account not activated" });
                    }

                } else {
                    res.send({ status: "invalid password" });
                }
            })
        }
    })
});

passport.serializeUser(function (user, done) {
    done(null, user);
});
passport.deserializeUser(function (user, done) {
    done(null, user);
});

//LOGOUT USER
app.get("/logout", (req, res) => {
    req.logout();
    req.session.destroy();
    res.redirect("/");
});


//NEW USER PAGE
app.get("/newuser", (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect("/");
    } else {
        res.render("newuser", { authenticationStatus: req.isAuthenticated(), aukaat: req.cookies.aukaat });
    }
});

app.post("/newuser", (req, res) => {
    var user = req.body;
    connection.query("SELECT * FROM user_data WHERE username = ?", [user.username], (err, rows) => {
        if (err) {
            console.log("error in checking duplicate username ;-(");
            res.send({ status: "SITE ERROR PLEASE TRY AGAIN LATER :-(" });
        } else if (rows.length != 0) {
            res.send({ status: "username not available" });
        } else {
            bcrypt.hash(user.password, saltRounds, (err, hash) => {
                if (err) {
                    console.log("error in hashing password");
                } else {
                    connection.query(`INSERT INTO user_data
                    (username, password, first, last, email, active_status, aukaat)
                    VALUES (?, ?, ?, ?, ?, ?, ?);`, [user.username, hash, user.first, user.last, user.email, 0, user.aukaat], (err) => {
                            if (err) {
                                console.log("error while inserting new user ;-(");
                                res.send({ status: "SITE ERROR PLEASE TRY AGAIN LATER :-(" });
                            } else {
                                console.log("User Registered: ");
                                console.log(user);
                                res.send({ status: "success" });

                                var activation_url = "http://localhost:2000/activate/" + cryptr.encrypt(user.username);

                                transporter.sendMail({
                                    from: "akshat.prodexiitkgp@gmail.com",
                                    to: user.email,
                                    subject: "Email Verification for Prodex Account",
                                    html: "<h3>Thank you for registering for Prodex IIT Kharagpur</h3><br><br><br><h5><a href=" + activation_url + ">Click Here</a> to verify </h5>"
                                }, (err, info) => {
                                    if (err) {
                                        console.log(err);
                                        console.log("error in sending mails ;-(");
                                    } else {
                                        console.log(info);
                                    }
                                });

                            }
                        });
                }
            })

        }
    })

});

//ACTIVATION OF ACCOUNTS

app.get("/activate/:encrypted_username", (req, res) => {
    var usernameToActivate = cryptr.decrypt(req.params.encrypted_username);
    connection.query("UPDATE user_data SET active_status = 1 WHERE username = ?", [usernameToActivate], (err) => {
        if (err) {
            console.log("error in activating account");
        } else {
            console.log("account activated for: " + usernameToActivate);
            res.redirect("/upload_profile_pic/" + req.params.encrypted_username);

            //PUT CODE TO MAKE JSONS PROFILE PICTURES AND ALL....
            //creating work profile json
            fs.writeFile(__dirname + "/tijori/works/" + usernameToActivate + ".json", "{ }", (err) => {
                if (err) {
                    console.log("Error in creaating work profile ;-(");
                }
            });

        }
    });
});

//PROFILE PAGE

app.get("/profile", (req, res) => {
    if (!req.isAuthenticated()) {
        res.redirect("/");
    } else {
        connection.query("SELECT * FROM user_data WHERE username = ?", [req.user], (err, rows) => {
            if (err || rows.length === 0) {
                console.log("error in retrieving user's data ;-(");
            } else {
                var userData = rows[0];
                userData.authenticationStatus = req.isAuthenticated();
                userData.aukaat= req.cookies.aukaat;
                res.render("profile", { userData });
            }
        })
    }
});

//ARTICLES PAGE
app.get("/articles", (req, res) => {
    //console.log(req.cookies);
    if (req.isAuthenticated()) {
        var articlePath = __dirname+"/tijori/articles/" + req.user + ".json";
        var articleList = {};
        if (fs.existsSync(articlePath)) {
            articleList = JSON.parse(fs.readFileSync(articlePath, 'utf8'));
        }
        articleList["authenticationStatus"] = req.isAuthenticated();
        res.render("articles", { list: articleList, aukaat: req.cookies.aukaat });
    } else {
        res.redirect("/");
    }
});

app.post("/articles", (req, res) => {
    if(req.isAuthenticated()) {
        var articlePath = "./tijori/articles/" + req.user + ".json";
        var json = JSON.parse(fs.readFileSync(articlePath, 'utf8'));
        console.log(json)
        json[ req.body.article ] = req.body.text;
        fs.writeFileSync(articlePath, JSON.stringify(json));
        res.send("completed")
        console.log("article named: "+ req.body.article +" edited by author")
    }
})

//NEW ARTICLE ENTRY PAGE

app.get("/newarticle", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("newarticle", { authenticationStatus: req.isAuthenticated(), aukaat: req.cookies.aukaat });
    } else {
        res.redirect("/login");
    }
});

app.post("/newarticle", (req, res) => {
    //console.log(req.body);
    var articlePath = "./tijori/articles/" + req.user + ".json";
    //console.log("file exists: ");
    //console.log(fs.existsSync(articlePath));
    if (fs.existsSync(articlePath)) {
        fs.readFile(articlePath, 'utf8', (err, data) => {
            if (err) {
                console.log("Error in reading JSON file");
            } else {
                // console.log(data);
                var articleSet = JSON.parse(data);
                //console.log(data);
                articleSet[(req.body).name] = (req.body).data;

                fs.writeFile(articlePath, JSON.stringify(articleSet), (err) => {
                    if (err) throw err;
                    else if (req.body.todo === "save") {
                        res.send({ status: "success" })
                        console.log("article -" + req.body.name + " saved by: " + req.user);
                    }
                });
            }
        });
    } else {
        var articleSet = {};
        articleSet[(req.body).name] = (req.body).data;
        fs.writeFile(articlePath, JSON.stringify(articleSet), (err) => {
            if (err) throw err;
            else if (req.body.todo === "save") {
                res.send({ status: "success" })
                console.log("article -" + req.body.name + " saved by: " + req.user);
            }
        });
    }

    if (req.body.todo === "sendToEditor") {
        var editorPath = "./tijori/articles/editor/" + req.user + ".json";
        if (fs.existsSync(editorPath)) {
            fs.readFile(editorPath, 'utf8', (err, data) => {
                if (err) {
                    console.log("Errror in sending article to editor")
                } else {
                    var editorSet = JSON.parse(data);
                    //console.log(editorSet);
                    editorSet[(req.body).name] = (req.body).data;

                    fs.writeFile(editorPath, JSON.stringify(editorSet), (err) => {
                        if (err) throw err;
                        else {
                            res.send({ status: "success" });
                            console.log("article -" + req.body.name + " sent to editor by: " + req.user);
                        }
                    });
                }
            });
        } else {
            var editorSet = {};
            editorSet[(req.body).name] = (req.body).data;

            fs.writeFile(editorPath, JSON.stringify(editorSet), (err) => {
                if (err) throw err;
                else {
                    res.send({ status: "success" });
                    console.log("article -" + req.body.name + " sent to editor by: " + req.user);
                }
            });
        }
    }



});

//PROFILE PHOTO UPLOAD PAGE
app.get("/upload_profile_pic/:encryptedUsername", (req, res) => {
    res.render("uploadprofilepic", {
        encryptedUsername: req.params.encryptedUsername, aukaat: req.cookies.aukaat
    });
});

app.post("/upload_profile_pic/:encryptedUsername", (req, res) => {
    if (Object.keys(req.files).length == 0) {
        return res.status(400).send('No Files Uploaded.');
    }

    var username = cryptr.decrypt(req.params.encryptedUsername);
    console.log(username);

    let sampleFile = req.files.sampleFile;

    sampleFile.mv(__dirname + "/tijori/profilePics/" + username + ".jpg", (err) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.redirect("/");
        }
    });
})

//EDITOR ARTICLE APPROVAL PAGE
app.get("/reviewarticle/editor", (req, res) => {
    const target = __dirname + "/tijori/articles/editor/"
    var files = fs.readdirSync(target);
    // console.log(files);

    var dataToSend = {};

    for (var i = 0; i < files.length; i++) {
        var file_name = files[i];
        // console.log(file_name);

        data = fs.readFileSync(target + file_name, 'utf8')

        var dataJson = JSON.parse(data);
        var keySet = [];
        for (key in dataJson) {
            //console.log(key);
            keySet.push(key)
        }
        //console.log(file);
        dataToSend[file_name] = keySet;
        //console.log("        ");
        // console.log("Inside Loop: ");
        // console.log(dataToSend);

    };


    // console.log("Outside Loop: ");
    // console.log(dataToSend);
    console.log("Editor fetched data for approval")
    res.render("editorarticles", { fileList: dataToSend, authenticationStatus: req.isAuthenticated() , aukaat: req.cookies.aukaat});
});

app.post("/reviewarticle/editor", (req, res) => {
    // console.log(req.body);
    const target = __dirname + "/tijori/articles/admin/"
    var articleLoc = target + req.body.user;
    if (fs.existsSync(articleLoc)) {
        var data = JSON.parse(fs.readFileSync(articleLoc, 'utf8'));
        data[req.body.article] = req.body.text
        fs.writeFile(articleLoc, JSON.stringify(data), (err) => {
            if (err) throw err;
            else {
                complete(req.body.user, req.body.article);
            }
        })
    } else {
        var dataSet = {}
        dataSet[req.body.article] = req.body.text
        fs.writeFile(articleLoc, JSON.stringify(dataSet), (err) => {
            if (err) throw err;
            else {
                complete(req.body.user, req.body.article);
            }
        })
    }

    function complete(user, article) {
        res.end("success");
        console.log("article named: " + article + "from user: " + user + " sent to admin by editor")
        fs.readFile(__dirname + "/tijori/articles/editor/" + user, 'utf8',(err, data) => {
            if(err) throw err
            else{
                var json = JSON.parse(data);
                delete json[ article ]
                fs.writeFile(__dirname + "/tijori/articles/editor/" + user, JSON.stringify(json), (err) => {
                    if(err) throw err
                });
            }
        })
    }
});

//ADMIN ARTICLE APPROVAL PAGE
app.get("/reviewarticle/admin", (req, res) => {

    const target = __dirname + "/tijori/articles/admin/"
    var files = fs.readdirSync(target);

    var dataToSend = {};

    for (var i = 0; i < files.length; i++) {
        var file_name = files[i];
        data = fs.readFileSync(target + file_name, 'utf8')

        var dataJson = JSON.parse(data);
        var keySet = [];
        for (key in dataJson) {
            keySet.push(key)
        }
        
        dataToSend[file_name] = keySet;
    };

    console.log("Admin fetched data for approval")
    res.render("adminarticles", { fileList: dataToSend, authenticationStatus: req.isAuthenticated() , aukaat: req.cookies.aukaat });
    
})

app.post("/reviewarticle/admin", (req, res) => {
    // console.log(req.body)
    if(req.body.todo == "SendBackToEditor"){
        const filePath = __dirname + "/tijori/articles/editor/" + req.body.user;
        var json = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        json[ req.body.article ] = req.body.text;
        fs.writeFileSync(filePath, JSON.stringify(json));
        res.send("success");
        console.log("article named: " +req.body.article+" sent back to editor for review")

        pursueAhead();

    }else if(req.body.todo == "sendToHomepage"){
        const filePath = __dirname + "/articles/" +req.body.article+ ".txt";
        fs.writeFile(filePath, req.body.text, (err) => {
            if(err) throw err;
        });
        res.send("success");
        console.log("new article named:"+req.body.article+" sent to Homepage")

        pursueAhead();
    }

    function pursueAhead(){
        const filePath = __dirname + "/tijori/articles/admin/" + req.body.user;
        fs.readFile(filePath, 'utf8', (err, data) => {
            if(err) throw err;
            else{
                var json = JSON.parse(data)
                delete json[ req.body.article ]
                fs.writeFile(filePath, JSON.stringify(json), (err) => {
                    if(err) throw err;
                });
            }
        });
    }
});


//PROJECTS PAGE
app.get("/projects", (req, res) => {
    var projectsGoingOn = [];
    var upcomingProjects = [];
    var projectsCompleted = [];
    connection.query("SELECT * FROM projects", (error, rows, fields) => {
        if(error) {
            console.log(error)
        }else{
            // console.log(rows)
            for(project in rows){
                project = rows[project]
                // console.log(project)
                if(project.status === "upcoming"){
                    upcomingProjects.push(project)
                }else if(project.status === "started"){
                    projectsGoingOn.push(project)
                }else if(project.status === "completed"){
                    projectsCompleted.push(project)
                }
            }
            console.log("Upcoming: "+JSON.stringify(upcomingProjects))
            console.log("Started: "+JSON.stringify(projectsGoingOn))

            res.render("projects", {authenticationStatus: req.isAuthenticated(), upcoming: upcomingProjects, started: projectsGoingOn, completed: projectsCompleted, aukaat: req.cookies.aukaat});

        }
    })

})


//NEW PROJECT PAGE

app.get("/new-project", (req, res) => {

    res.render("newproject", {authenticationStatus : req.isAuthenticated()});

})

app.post("/new-project", (req, res) => {
    console.log(req.body);

    connection.query("INSERT INTO projects (name, details, summary, status, budget) VALUES (?,?,?,'upcoming', ?);", [req.body.name, req.body.details, req.body.summary, parseInt(req.body.budget)], (err) => {
        if(err){
            console.log("error in adding new project to DB :-(");
        }else{
            console.log(`admin added new project : ${req.body.name} with budget: ₹${req.body.budget}`);
            res.send("recieved!");
        }
    });

})


// IDEA SUBMISSION PAGE

app.get("/submit-idea", (req, res) => {

    res.render("newidea");

})

app.post("/submit-idea", (req, res) => {

    // console.log(req.body)
    connection.query("INSERT INTO ideas (name, summary, idea) VALUES (?, ?, ?);", [req.body.name, req.body.summary, req.body.idea], (err) => {
        if(err){
            console.log("Error in submitting idea ;-(");
            res.end("error!");
            throw err;
        }else{
            res.send("success!");
            console.log(`new idea submitted by: ${req.body.name}`);
        }
    })

})


//PROFILE PHOTO FETCH HANDLER
app.get("/taikhana/images/:username", (req, res) => {
    if (req.isAuthenticated() && req.user === req.params.username) {
        console.log("image fetched from taikhana for: " + req.params.username);
        res.sendFile(__dirname + "/tijori/profilePics/" + req.params.username + ".jpg");
    } else {
        res.send("non accessible");
    }
});

//WORK PROFILE FETCH HANDLER
app.get("/taikhana/works/:username", (req, res) => {
    if (req.isAuthenticated() && req.user === req.params.username) {
        console.log("work data fetched from taikhana for: " + req.params.username);
        res.sendFile(__dirname + "/tijori/works/" + req.params.username + ".json");
    } else {
        res.send("non accessible");
    }

});

//EDITOR ARTICLE FETCH FOR APPROVAL HANDLER
app.post("/editorArticleFetch", (req, res) => {
    console.log("editor fetched data for user: " + req.body.user + ", article name:" + req.body.article)

    const target = __dirname + "/tijori/articles/editor/"
    var data = fs.readFileSync(target + req.body.user, 'utf8')
    data = JSON.parse(data)
    var articleText = data[req.body.article]

    res.send(articleText)
})

//ADMIN ARTICLE FETCH FOR APPROVAL HANDLER
app.post("/adminArticleFetch", (req, res) => {
    console.log("admin fetched data for user: " + req.body.user + ", article name:" + req.body.article)

    const target = __dirname + "/tijori/articles/admin/"
    var data = fs.readFileSync(target + req.body.user, 'utf8')
    data = JSON.parse(data)
    var articleText = data[req.body.article]

    res.send(articleText)
})


//START SERVER
app.listen(2000, () => {
    console.log("server started on port http://localhost:2000 :-)");
});