const { Schema, model } = require('mongoose');
const userSchema = new Schema({
    login: String,
    password: String,
    registrationDate: { type: Number, default: Date.now },
    isBanned: { type: Boolean, default: false }
});

module.exports = model('users', userSchema);