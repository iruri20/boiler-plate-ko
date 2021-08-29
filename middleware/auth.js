const { User } = require("../models/User");

let auth = (req, res, next) => {

    // 인증 처리

    // 클라이언트 쿠키에서 token을 가져 옴
    let token = req.cookies.x_auth;

    // token을 복호화한 후 user를 찾는다
    User.findByToken(token, (err, user) => {
        if (err) throw err;

        if (!user) return res.json( { isAuth: false, error: true });

        req.token = token;
        req.user = user;
        next();
    });

    // user가 있으면 인증 OK

    // user가 없으면 인증 fail
}

module.exports = { auth };