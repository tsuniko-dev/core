const secret = "***";
const messageSecret = "***";

const crypto = require('crypto');
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
        try {
            let decipher = crypto.createDecipher('aes192', messageSecret);
            data.message = decipher.update(data.message, 'hex', 'utf8') + decipher.final('utf8');
            return console.info(`NEW MESSAGE | [${data.login}] ${data.message}`);
        } catch (e) {}
    });

    io.emit('login', {
        login: "***",
        password: "***", secret
    });

    function sendMessage(text) {
        let cipher = crypto.createCipher('aes192', messageSecret);
        let message = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
        io.emit('message', { message, secret });
    }

    setTimeout(() => {
        sendMessage('test message! maybe..');
    }, 2000);
});