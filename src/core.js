const fs = require('fs');
const https = require('https');
const mongoose = require('mongoose');
const express = require('express');

const config = require('./config.json');
const app = express();

app.use((req, res, next) => {
    console.log(`* [Request] ${req.ip} | ${req.path}`);
    return next();
});
app.use(require('helmet')({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "cdnjs.cloudflare.com"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [],
        }
    }
}));
app.use('/', express.static('src/public'));

const server = https.createServer({
    key: fs.readFileSync(__dirname + config.ssl.key),
    cert: fs.readFileSync(__dirname + config.ssl.cert)
}, app).listen(process.env.PORT || config.port, config.host, () =>
    console.log(`* Listening requests on *:${process.env.PORT || config.port}...`)
);

const io = require('socket.io')(server);
mongoose.connect(config.database, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.connection.on('error', console.error);
mongoose.connection.once('open', () => console.info("* Connected to database"));

const Users = require('./models/users');
const crypto = require('crypto');

io.joined = [];
io.on('connection', (socket) => {
    if(socket.handshake.auth.secret !== config.secret) return socket.disconnect();
    
    console.log(`* ${socket.id} has connected`);
    socket.on('login', (data) => {
        let { login, password, secret } = data;
        if(!login || !password || !secret) return;
        if(secret !== config.secret) return socket.emit('notifications', { type: "login", success: false, data: [], errors: ['Incorrect secret key'] });

        if(io.joined.find(user => user.login == login)) return socket.emit('notifications', { type: "login", success: false, data: [], errors: ['User already authorized'] });
        if(io.joined.find(user => user._id == socket.id)) return socket.emit('notifications', { type: "login", success: false, data: [], errors: ['You already authorized'] });
        
        let cipher = crypto.createCipher('aes192', config.secret);
        let encryptedKey = cipher.update(login + password + secret, 'utf8', 'hex');
        encryptedKey += cipher.final('hex');

        Users.findOne({ login, password: encryptedKey }, (err, user) => {
            if(err) throw err;
            if(!user) return socket.emit('notifications', { type: "login", success: false, data: [], errors: ['User not found'] });
            if(user.isBanned == true) return socket.emit('notifications', { type: "login", success: false, data: [], errors: ['User has been banned'] });

            io.joined.push({ _id: socket.id, login: user.login });
            console.log(`* ${socket.id} has been authorized as ${user.login}`);
            return socket.emit('notifications', { type: "login", success: true, data: [], errors: [] });
        });
    });

    socket.on('registration', (data) => {
        let { login, password, secret } = data;
        if(!login || !password || !secret) return;
        if(secret !== config.secret) return socket.emit('notifications', { type: "registration", success: false, data: [], errors: ['Incorrect secret key'] });

        if(io.joined.find(user => user.login == login)) return socket.emit('notifications', { type: "registration", success: false, data: [], errors: ['User already registered'] });
        if(io.joined.find(user => user._id == socket.id)) return socket.emit('notifications', { type: "registration", success: false, data: [], errors: ['You already registered'] });
        
        let cipher = crypto.createCipher('aes192', config.secret);
        let encryptedKey = cipher.update(login + password + secret, 'utf8', 'hex');
        encryptedKey += cipher.final('hex');
        
        Users.findOne({ login, password: encryptedKey }, (err, user) => {
            if(err) throw err;
            if(user) return socket.emit('notifications', { type: "registration", success: false, data: [], errors: ['User already registered'] });

            user = new Users({ login, password: encryptedKey });
            user.save();
            return socket.emit('notifications', { type: "registration", success: true, data: [user], errors: [] });
        });
    });

    socket.on('change_username', (data) => {
        let { login, new_login, password, secret } = data;
        if(!login || !new_login || !password || !secret) return;
        if(secret !== config.secret) return socket.emit('notifications', { type: "change_username", success: false, data: [], errors: ['Incorrect secret key'] });

        if(!io.joined.find(user => user.login == login)) return socket.emit('notifications', { type: "change_username", success: false, data: [], errors: ['User not authorized'] });
        if(!io.joined.find(user => user._id == socket.id)) return socket.emit('notifications', { type: "change_username", success: false, data: [], errors: ['You not authorized'] });
        if(io.joined.find(user => user._id == socket.id).login !== login) return socket.emit('notifications', { type: "change_username", success: false, data: [], errors: ['You not own provided account'] });

        let cipher = crypto.createCipher('aes192', config.secret);
        let encryptedKey = cipher.update(login + password + secret, 'utf8', 'hex');
        encryptedKey += cipher.final('hex');

        Users.findOne({ login, password: encryptedKey }, (err, user) => {
            if(err) throw err;
            if(!user) return socket.emit('notifications', { type: "change_username", success: false, data: [], errors: ['User not found'] });
            if(user.isBanned == true) return socket.emit('notifications', { type: "change_username", success: false, data: [], errors: ['User has been banned'] });

            cipher = crypto.createCipher('aes192', config.secret);
            encryptedKey = cipher.update(new_login + password + secret, 'utf8', 'hex');
            encryptedKey += cipher.final('hex');

            user = new Users(user);
            user.login = new_login;
            user.password = encryptedKey;
            user.save();

            console.log(`* ${socket.id} (${io.joined.find(user => user._id == socket.id).login}) has changed username to ${new_login}`);
            socket.emit('notifications', { type: "change_username", success: true, data: ['Changing username is broke your session. Please re-login.'], errors: [] });
            return socket.disconnect();
        });
    });

    socket.on('change_password', (data) => {
        let { login, new_password, password, secret } = data;
        if(!login || !new_password || !password || !secret) return;
        if(secret !== config.secret) return socket.emit('notifications', { type: "change_password", success: false, data: [], errors: ['Incorrect secret key'] });

        if(!io.joined.find(user => user.login == login)) return socket.emit('notifications', { type: "change_password", success: false, data: [], errors: ['User not authorized'] });
        if(!io.joined.find(user => user._id == socket.id)) return socket.emit('notifications', { type: "change_password", success: false, data: [], errors: ['You not authorized'] });
        if(io.joined.find(user => user._id == socket.id).login !== login) return socket.emit('notifications', { type: "change_password", success: false, data: [], errors: ['You not own provided account'] });

        let cipher = crypto.createCipher('aes192', config.secret);
        let encryptedKey = cipher.update(login + password + secret, 'utf8', 'hex');
        encryptedKey += cipher.final('hex');

        Users.findOne({ login, password: encryptedKey }, (err, user) => {
            if(err) throw err;
            if(!user) return socket.emit('notifications', { type: "change_password", success: false, data: [], errors: ['User not found'] });
            if(user.isBanned == true) return socket.emit('notifications', { type: "change_password", success: false, data: [], errors: ['User has been banned'] });

            cipher = crypto.createCipher('aes192', config.secret);
            encryptedKey = cipher.update(login + new_password + secret, 'utf8', 'hex');
            encryptedKey += cipher.final('hex');

            user = new Users(user);
            user.password = encryptedKey;
            user.save();

            socket.emit('notifications', { type: "change_password", success: true, data: ['Please re-login.'], errors: [] });
            return socket.disconnect();
        });
    });

    socket.on('message', (data) => {
        let { message, secret } = data;
        if(!message || !secret) return;
        if(secret !== config.secret) return socket.emit('notifications', { type: "message", success: false, data: [], errors: ['Incorrect secret key'] });

        if(!io.joined.find(user => user._id == socket.id)) return socket.emit('notifications', { type: "message", success: false, data: [], errors: ['You not authorized'] });
        io.emit('messages', { login: io.joined.find(user => user._id == socket.id).login, message });
        return socket.emit('notifications', { type: "message", success: true, data: [], errors: [] });
    });

    socket.on('session', (data) => {
        let { secret } = data;
        if(!secret) return;
        if(secret !== config.secret) return socket.emit('notifications', { type: "session", success: false, data: [], errors: ['Incorrect secret key'] });

        if(!io.joined.find(user => user._id == socket.id)) return socket.emit('notifications', { type: "session", success: false, data: [], errors: ['You not authorized'] });
        return socket.emit('notifications', { type: "session", success: true, data: [io.joined.find(user => user._id == socket.id)], errors: [] });
    });

    socket.on('disconnect', () => {
        let user = io.joined.find(user => user._id == socket.id);
        if(user) io.joined = io.joined.filter(user => user._id !== socket.id);
        console.log(`* ${socket.id} (${user ? user.login : "Unauthorized"}) has disconnected`);
    });
});