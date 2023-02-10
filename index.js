// Import express
let express = require('express');
// Import Body parser
let bodyParser = require('body-parser');
// Initialise the app
let app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const Role = require('./role');

require('dotenv').config()

app.use(cors())

// Configure bodyparser to handle post requests
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

// Setup server port
const port = process.env.PORT || 8082;

app.get('/users', authenticate_and_authorize(Role.Admin), (req, res) => {
    res.sendStatus(202);
    // res.json( req.user.role );
})

app.get('/register', (req, res) => {

    const username = req.body.username;
    const role = req.body.role;
    const user = {username: username, role: role}

    // Create access token
    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECERT)
    res.json({accessToken: accessToken});
})


function authenticate_and_authorize(roles = []) {
    return (req, res, next) => {
        const authHeader = req.headers['authorization']; // Bearer token
        const bearerToken = authHeader && authHeader.split(' ')[1];
        if (bearerToken == null) return res.sendStatus(401);
        if (typeof roles === 'string') roles = [roles];

        // Authenticate user's access token
        jwt.verify(bearerToken, process.env.ACCESS_TOKEN_SECERT, (err, user) => {
            // user not authenticated
            if (err) return res.sendStatus(401);
            req.user = user;
            // Authorize user's role
            if (roles.length && !roles.includes(req.user.role)) {
                // user's role is not authorized
                return res.sendStatus(403);
            }
            // Move on from our middleware
            next();
        })
    }
}

// Launch app to listen to specified port
app.listen(port, function () {
    console.log("Running library on port " + port);
});
module.exports = app;
