
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

	const schema = Joi.string().max(100).required();
	const validationResult = schema.validate(name);

    var invalid = false;

	if (validationResult.error != null) { 
        invalid = true;
	    console.log(validationResult.error);

	}	
    var numRows = -1;
    try {
    	const result = await userCollection.find({userame: username}).project({username: 1, password: 1, _id: 1}).toArray();

        numRows = result.length;
    }
    catch (err) {
        console.log(err);
        res.send(`<h1>Error querying db</h1>`);
        return;
    }

    console.log(`invalid: ${invalid} - numRows: ${numRows} - user: `,name);

    res.send(`<h1>Hello</h1> <h3> num rows: ${numRows}</h3>`); 

});

app.get('/', async (req, res) => {
    if (!req.session.authenticated) {
		return 	res.render("index");
	  }
	  var username = req.session.username;
	  res.render("loggedin",{username: username});

});


app.get('/signup', (req, res) => {
    var isAuthenticated = req.session.authenticated || false;
    res.render("signup", { authenticated: isAuthenticated });
  });


app.get('/login', (req, res) => {
    var isAuthenticated = req.session.authenticated;
    res.render("login", { authenticated: isAuthenticated });
});

app.get('/loggedin', (req, res) => {
    var isAuthenticated = req.session.authenticated;

    res.render("loggedin", { authenticated: isAuthenticated });
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!username) {
        res.render("missing", { error: "Name" });
    }
    if (!email) {
        res.render("missing", { error: "Email" });
    }
    if (!password) {
        res.render("missing", { error: "Password" });
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
    res.redirect("/missing");
    return;
}

var hashedPassword = await bcrypt.hash(password, saltRounds);

await userCollection.insertOne({ username: username, email: email, password: hashedPassword, user_type: "user"});
req.session.authenticated = true;
req.session.email = email;
req.session.username = username;
req.session.cookie.maxAge = expireTime;

console.log("Inserted user");
res.render("loggedin", {username: username});

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

    const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, user_type: 1,_id: 1 }).toArray();

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
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
        return;        
    }
    else {
        console.log("incorrect password");
        res.redirect('/login');
    return;        
    }
});

// app.use('/members', );
app.get('/members',sessionValidation, (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var username = req.session.username;
    res.render("members", {username: username});

});


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.render("logout");
    });


app.get("/admin", sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({ username: 1, user_type: 1 }).toArray();
    var isAuthenticated = req.session.authenticated || false;
 
    res.render("admin", {users: result, username: req.session.username, user_type: req.session.user_type, authenticated: isAuthenticated});
});


app.post('/demote/:username', async (req, res) => {
    const username = req.params.username;
      await userCollection.updateOne({ username: username }, { $set: { user_type: "user" } });
      console.log("User demoted");

  });
  
  app.post('/promote/:username', async (req, res) => {
    const username = req.params.username;
      await userCollection.updateOne({ username: username }, { $set: { user_type: "admin" } });
      console.log("User promoted");

  });


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 