
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const port = process.env.PORT || 3000;
const app = express();
const Joi = require("joi");
const expireTime = 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})


app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}
));

function isValidSession(req) {
    // return req.session.authenticated; //this line is the same as below
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

//middleware function - "next"
function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    //return req.session.user_type = "admin"; // this line is the same as below
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

//middleware - 403 Forbidden
function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}


app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	//console.log("user: "+username);

	const schema = Joi.string().max(100).required();
	const validationResult = schema.validate(name);

    var invalid = false;

	if (validationResult.error != null) { 
        invalid = true;
	    console.log(validationResult.error);
	//    res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	//    return;
	}	
    var numRows = -1;
    //var numRows2 = -1;
    try {
    	const result = await userCollection.find({userame: username}).project({username: 1, password: 1, _id: 1}).toArray();
    	//const result2 = await userCollection.find("{name: "+name).project({username: 1, password: 1, _id: 1}).toArray(); //mongoDB already prevents using catenated strings like this
        //console.log(result);
        numRows = result.length;
        //numRows2 = result2.length;
    }
    catch (err) {
        console.log(err);
        res.send(`<h1>Error querying db</h1>`);
        return;
    }

    console.log(`invalid: ${invalid} - numRows: ${numRows} - user: `,name);

    // var query = {
    //     $where: "this.name === '" + req.body.username + "'"
    // }

    // const result2 = await userCollection.find(query).toArray(); //$where queries are not allowed.
    
    // console.log(result2);

    res.send(`<h1>Hello</h1> <h3> num rows: ${numRows}</h3>`); 
    //res.send(`<h1>Hello</h1>`);

});

app.get('/', async (req, res) => {
    res.render("index");
});


app.get('/signup', (req, res) => {
    res.render("signup");
});


app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

let err = "";
if (!username) {
    err += "Please enter your Name.  <br> ";
}
if (!email) {
    err += "Please enter your Email.  <br> ";
}
if (!password) {
    err += "Please enter your Password. <br> ";
}
if (err !== "") {
    err += "<a href='/signup'>Try again</a>";
    res.send(err);
    return;
}


const schema = Joi.object(
    {
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

const validationResult = schema.validate({ username, email, password });
if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signup");
    return;
}

var hashedPassword = await bcrypt.hash(password, saltRounds);

await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
console.log("Inserted user");
    var html = "successfully created user"
    res.render("submitUser", {html: html});
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/login"); //?error-user-not-found
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        res.render("login")
        
    }
});

app.use('/members, sessionValidation');
app.get('/members', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }

    res.render("/members");

});


app.get('/logout', (req, res) => {
    res.render("logout");
    });



    
app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1, _id: 1}).toArray(); // password: 1,

    res.render("admin", {users: result});
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 