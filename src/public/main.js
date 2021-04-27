// TODO: CryptoJS source import
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
    messageSecret: "Type a key for crypt/decrypt your messages:"
};

let secret, login, password;
if(!localStorage.getItem('secret')) {
    secret = prompt(prompts.secret);
    if(!secret || secret == null) secret = prompt(prompts.secret);
    localStorage.setItem('secret', secret);
}

if(!localStorage.getItem('login')) {
    login = prompt(prompts.login);
    if(!login || login == null) login = prompt(prompts.login);
    localStorage.setItem('login', login);
}

if(!localStorage.getItem('password')) {
    password = prompt(prompts.password);
    if(!password || password == null) password = prompt(prompts.password);
    localStorage.setItem('password', password);
}

if(!localStorage.getItem('messageSecret')) {
    messageSecret = prompt(prompts.messageSecret);
    if(!messageSecret || messageSecret == null) messageSecret = prompt(prompts.messageSecret);
    localStorage.setItem('messageSecret', messageSecret);
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
        if(data.type == "login" && data.success == false) {
            localStorage.clear();
        }
        alert(`${processedTypes[data.type]}: ${(data.success) ? data.data[0] || "Successful." : data.errors[0]|| "Failed."}`);
    });

    socket.on('messages', (data) => {
        try {
            data.message = CryptoJS.AES.decrypt(data.message, localStorage.getItem('messageSecret'));
            data.message = data.message.toString(CryptoJS.enc.Utf8);
            return console.info(`NEW MESSAGE | [${data.login}] ${data.message}`);
        } catch (e) {}
    });

    socket.emit('login', {
        login: localStorage.getItem('login'),
        password: localStorage.getItem('password'),
        secret: localStorage.getItem('secret')
    });
});

function sendMessage(socket, text) {
    let message = CryptoJS.AES.encrypt(text, localStorage.getItem('messageSecret')).toString();
    socket.emit('message', { message, secret: localStorage.getItem('secret') });
}