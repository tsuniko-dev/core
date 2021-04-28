// TODO: UI Interface

let processedTypes = {
    login: 'Authorization',
    notifications: 'Notify',
    registration: 'Registration',
    change_username: 'Change a username',
    change_password: 'Change a password',
    session: 'Session'
};

let prompts = {
    secret: "Type a socket connect token:",
    login: "Type a login:",
    password: "Type a password:",
    messageSecret: "Type a key for crypt/decrypt your messages:",
    not_provided: "You can't to provide data? Sorry, but we don't access you to chat."
};

let secret, login, password;
if(!localStorage.getItem('secret')) {
    secret = prompt(prompts.secret);
    if(!secret || secret == null) secret = prompt(prompts.secret);
    if(!secret || secret == null) alert(prompts.not_provided);
    if(secret && secret !== null) localStorage.setItem('secret', secret);
}

if(!localStorage.getItem('login')) {
    login = prompt(prompts.login);
    if(!login || login == null) login = prompt(prompts.login);
    if(!login || login == null) alert(prompts.not_provided);
    if(login && login !== null) localStorage.setItem('login', login);
}

if(!localStorage.getItem('password')) {
    password = prompt(prompts.password);
    if(!password || password == null) password = prompt(prompts.password);
    if(!password || password == null) alert(prompts.not_provided);
    if(password && password !== null) localStorage.setItem('password', password);
}

if(!localStorage.getItem('messageSecret')) {
    messageSecret = prompt(prompts.messageSecret);
    if(!messageSecret || messageSecret == null) messageSecret = prompt(prompts.messageSecret);
    if(!messageSecret || messageSecret == null) alert(prompts.not_provided);
    if(messageSecret && messageSecret !== null) localStorage.setItem('messageSecret', messageSecret);
}

const socket = io('', { auth: { secret: localStorage.getItem('secret') } });
socket.on("connect_error", (err) => {
    if(err) {
        console.error(err);
        return alert('An error has been occurred. Check the console.');
    }
});

socket.on("connect", async () => {
    console.log("* Connected");

    socket.on('notifications', (data) => {
        if(data.type == "login" && data.success == false && ![
            'User already authorized',
            'You already authorized',
            'User has been banned'
        ].includes(data.errors[0])) { localStorage.clear(); }
        if(data.type !== "message") alert(`${processedTypes[data.type]}: ${(data.success) ? data.data[0] || "Successful." : data.errors[0]|| "Failed."}`);
    });

    socket.on('messages', (data) => {
        try {
            data.message = CryptoJS.AES.decrypt(data.message, localStorage.getItem('messageSecret'), { mode: CryptoJS.mode.OFB });
            data.message = data.message.toString(CryptoJS.enc.Utf8);
            if(data.message.length >= 1) return console.info(`[${data.login}] ${data.message}`);
        } catch (e) {}
    });

    socket.emit('login', {
        login: localStorage.getItem('login'),
        password: localStorage.getItem('password'),
        secret: localStorage.getItem('secret')
    });
});

function sendMessage(socket, text) {
    let message = CryptoJS.AES.encrypt(text, localStorage.getItem('messageSecret'), { mode: CryptoJS.mode.OFB }).toString();
    socket.emit('message', { message, secret: localStorage.getItem('secret') });
}