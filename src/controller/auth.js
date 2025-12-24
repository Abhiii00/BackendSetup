const userModel = require('../model/userModel');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const MSG = require('../utils/msgResponse');

/* ------------------ REGISTER ------------------ */
exports.register = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const exists = await userModel.findOne({ email });
        if (exists) return res.status(400).send({ success: false, message: MSG.AUTH.EMAIL_EXISTS });

        const hashedPass = await bcrypt.hash(password, 10);

        const user = await userModel.create({ name, email, password: hashedPass });

        return res.status(201).send({ success: true, message: MSG.AUTH.USER_CREATED, data: user });

    } catch (err) {
        return res.status(500).send({ success: false, message: MSG.COMMON.SERVER_ERROR, error: err.message });
    }
};

/* ------------------ LOGIN ------------------ */
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).send({ success: false, message: MSG.AUTH.USER_NOT_FOUND });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).send({ success: false, message: MSG.AUTH.INVALID_PASSWORD });

        user.isLogout = false;
        await user.save();

        const accessToken = jwt.sign({ id: user._id, type: "access" }, process.env.JWT_SECRET, { expiresIn: "15m" });
        const refreshToken = jwt.sign({ id: user._id, type: "refresh" }, process.env.JWT_SECRET, { expiresIn: "7d" });

        return res.status(200).send({
            success: true,
            message: MSG.AUTH.LOGIN_SUCCESS,
            data: { user: { _id: user._id, name: user.name, email: user.email }, accessToken, refreshToken }
        });

    } catch (err) {
        console.log(err.message)
        return res.status(500).send({ success: false, message: MSG.COMMON.SERVER_ERROR });
    }
};

/* ------------------ REFRESH TOKEN ------------------ */
exports.refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) return res.status(401).send({ success: false, message: MSG.AUTH.TOKEN_MISSING });

        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        if (decoded.type !== "refresh") return res.status(401).send({ success: false, message: MSG.AUTH.INVALID_TOKEN });

        const user = await userModel.findById(decoded.id);
        if (!user || user.isLogout) return res.status(401).send({ success: false, message: MSG.AUTH.INVALID_TOKEN });

        const newAccessToken = jwt.sign({ id: user._id, type: "access" }, process.env.JWT_SECRET, { expiresIn: "15m" });

        return res.status(200).send({ success: true, data: { accessToken: newAccessToken } });

    } catch (err) {
        return res.status(500).send({ success: false, message: MSG.AUTH.INVALID_TOKEN });
    }
};

/* ------------------ LOGOUT ------------------ */
exports.logout = async (req, res) => {
    try {
        await userModel.findByIdAndUpdate(req.user.id, { isLogout: true });

        return res.status(200).send({ success: true, message: MSG.AUTH.LOGOUT_SUCCESS });

    } catch (err) {
        console.log(err.message)
        return res.status(500).send({ success: false, message: MSG.COMMON.SERVER_ERROR });
    }
};
