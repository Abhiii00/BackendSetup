const jwt = require('jsonwebtoken');
const userModel = require('../model/userModel');
const MSG = require('../utils/msgResponse');

module.exports = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).send({ success: false, message: MSG.AUTH.TOKEN_MISSING });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await userModel.findById(decoded.id);
        if (!user || user.isLogout) return res.status(401).send({ success: false, message: MSG.AUTH.INVALID_TOKEN });

        req.user = decoded;
        next();

    } catch (err) {
        return res.status(401).send({ success: false, message: MSG.AUTH.INVALID_TOKEN });
    }
};
