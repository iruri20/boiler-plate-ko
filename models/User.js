const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true,     // 공간을 없애줌  (문자열 중간 포함)
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

// 'pre'는 Mongoose에서 제공하는 function으로써,
// 아래는 Mongo DB 'save' 하기 전, 뭔가 실행
userSchema.pre('save', function( next ) {  // 아래 문장 수행후 'next' 수행
    var user = this;

    if (user.isModified('password')) {
        // 비밀번호 암호화
       bcrypt.genSalt(saltRounds, function(err, salt) {   // function(err, salt): callback function으로써 돌려받는 값임
            if (err) {
                console.log('err');
                return next(err)
            }

            bcrypt.hash(user.password, salt, function (err, hash) {
                if (err)  return next(err)

                user.password = hash;
                next();
            })
        })
    } else {
        next();
    }
});

userSchema.methods.comparePassword = function(plainPassword, cb) {
    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if (err) return cb(err)

        cb(null, isMatch);
    })
}

userSchema.methods.generateToken = function(cb) {
    var user = this;

    // jsonwebtoken을 이용해서 token 생성.  token = sign(user._id + secretToken)
    var token = jwt.sign(user._id.toHexString(), 'secretToken');

    user.token = token;
    user.save(function(err, user) {
        if (err)  return cb(err)
        cb(null, user);
    })
}

userSchema.statics.findByToken = function(token, cb) {
    var user = this;

    // token decode
    jwt.verify(token, 'secretToken', function(err, decoded) {
        // user._id를 이용해서 user를 찾은 후,
        // 클라이언트에서 가져온 token과 일치하는 지 확인

        user.findOne({"_id": decoded, "token": token }, function(err, user) {
            if (err) return cb(err);

            cb(null, user);
        })
    })
}

const User = mongoose.model('User', userSchema)

module.exports = { User }