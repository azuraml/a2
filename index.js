
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
    resave: false
}
));

app.get('/', async (req, res) => {
    if (!req.session.authenticated) {
        var html = `
        Welcome
        <div><button><a href="/signup">Sign Up</a></button></div>
        <div><button><a href="/login">Log In</a></button></div>
    `;
        res.send(html);
        return;
    }
    else {
        req.session.isAuth = true;
        console.log(req.session);
        var name = await userCollection.find({ email: req.session.email }).project({}).toArray();

        const html =
        `<h1>Hello ${name[0].username} !</h1>   
        <div><button><a href="/members">Members Page</a></button></div>
        <div><button><a href="/logout">Log out</a></button></div>
        `;
        res.send(html);
        return;
    }
});


app.get('/signup', (req, res) => {
    var html = `
    Sign Up
    <form action='/submitUser' method='post'>
    <div><input name='username' type='text' placeholder='name'></div>
    <div><input name='email' type='email' placeholder='email'></div>
    <div><input name='password' type='password' placeholder='password'></div>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <div><input name='email' type='email' placeholder='email'></div>
    <div><input name='password' type='password' placeholder='password'></div>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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

    var html = `successfully created user         
    <div><button><a href='/login'>Log In</a></button></div>
    `;
    res.send(html);
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
        res.redirect("/login?error-user-not-found");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        res.send("Incorrect password, <a href='/login'>Try again</a>");
        return;
    }
});

app.get('/members', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    var name = await userCollection.find({ email: req.session.email }).project({}).toArray();

    const images = ['1.png', '2.png', '3.png'];
    const selectedImage = images[Math.floor(Math.random() * images.length)];

    const html =
    `<h1>Hello ${name[0].username}</h1>
    <img src='${selectedImage}' alt='random image'>  
    <div><button><a href="/logout">Sign Out</a></button></div>
    `;
    res.send(html);

});


app.get('/logout', (req, res) => {

    req.session.destroy();
        var html = `
    <p> You are logged out! <p>  
    <div><button><a href="/">Home</a></button></div>

    `;
        res.send(html);
    });



app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 