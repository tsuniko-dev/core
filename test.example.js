const secret = "***";
const crypto = require('crypto');
const cipher = crypto.createCipher('aes192', secret);
const decipher = crypto.createDecipher('aes192', secret);

const io = require('socket.io-client')('ws://localhost:8080', {
    allowEIO3: true,
    auth: { secret }
});

io.on("connect_error", (err) => {
    if(err) return console.error(err);
});

io.on("connect", async () => {
    console.log("* Connected");

    io.on('notifications', (data) =>
        console.info(`NOTIFY | [${data.type}] ${(data.success) ? data.data[0] || "nothing.. just true" : data.errors[0]}`)
    );

    io.on('messages', (data) => {
        data.message = decipher.update(data.message, 'hex', 'utf8') + decipher.final('utf8');
        return console.info(`NEW MESSAGE | [${data.login}] ${data.message}`);
    });

    io.emit('login', {
        login: "***",
        password: "***", secret
    });

    setTimeout(() => {
        let message = cipher.update("test message! maybe..", 'utf8', 'hex') + cipher.final('hex');
        io.emit('message', { message, secret });
    }, 2000);
});